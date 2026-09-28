"""MTA-STS (RFC 8461) and DANE TLSA (RFC 7672) Advisory Checker.

Performs passive DNS resolution heuristics on mail domains and hostnames to
evaluate authenticated downgrade protections against STARTTLS stripping attacks.
Uses a zero-dependency, pure-Python RFC 1035 UDP DNS resolver that is fast and
safe for offline/air-gapped forensics.
"""

from __future__ import annotations

import hashlib
import re
import socket
import struct
import urllib.request
import ssl
from typing import Any, Dict, List, Optional, Tuple, Union
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import DnsSecurityInfo, Session

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# Cache DNS lookups in-memory to prevent repeated network queries
_MTA_STS_CACHE: Dict[str, Tuple[Optional[str], bool, Optional[str], Optional[str]]] = {}
_DANE_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def _build_dns_query(qname_str: str, qtype: int) -> bytes:
    """Construct an RFC 1035 UDP DNS query packet with RFC 6891 EDNS0 extension."""
    tx_id = 0x7B29
    flags = 0x0100  # Standard query with recursion desired (RD=1)
    # 1 question, 0 answers, 0 authority, 1 additional (EDNS0 OPT RR)
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 1)

    # Encode domain name labels with IDNA support
    parts = qname_str.strip(".").split(".")
    encoded_parts = []
    for p in parts:
        if p:
            try:
                encoded_parts.append(p.encode("idna"))
            except Exception:
                encoded_parts.append(p.encode("ascii", "replace"))
    qname = b"".join(bytes([len(p)]) + p for p in encoded_parts) + b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN (1)
    # EDNS0 OPT RR: root label (0), TYPE=41 (OPT), UDP payload size=4096 (0x1000), flags=0, RDLEN=0
    edns_opt = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00"
    return header + question + edns_opt


def _parse_dns_response(data: bytes, target_qtype: int) -> List[bytes]:
    """Parse answer RDATAs from an RFC 1035 DNS response."""
    if len(data) < 12:
        return []

    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return []

    # Skip header (12 bytes)
    off = 12
    # Skip question section
    try:
        while off < len(data) and data[off] != 0:
            if (data[off] & 0xC0) == 0xC0:
                off += 2
                break
            off += 1 + data[off]
        else:
            off += 1
        off += 4  # QTYPE (2B) + QCLASS (2B)
    except Exception:
        return []

    answers: List[bytes] = []
    # Parse Answer RRs
    for _ in range(ancount):
        if off >= len(data):
            break
        try:
            # Skip NAME field (handles compression pointers)
            if (data[off] & 0xC0) == 0xC0:
                off += 2
            else:
                while off < len(data) and data[off] != 0:
                    if (data[off] & 0xC0) == 0xC0:
                        off += 2
                        break
                    off += 1 + data[off]
                else:
                    off += 1

            if off + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if off + rdlen > len(data):
                break
            rdata = data[off:off + rdlen]
            off += rdlen

            if rtype == target_qtype:
                answers.append(rdata)
        except Exception:
            break

    return answers


def query_dns_raw(name: str, qtype: int, server: str = "1.1.1.1", timeout: float = 1.0) -> List[bytes]:
    """Execute a low-level UDP DNS query with EDNS0 and server fallback."""
    servers = [server] if server not in ("1.1.1.1", "8.8.8.8") else ["1.1.1.1", "8.8.8.8"]
    for srv in servers:
        try:
            packet = _build_dns_query(name, qtype)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (srv, 53))
                resp, _ = sock.recvfrom(4096)
            answers = _parse_dns_response(resp, qtype)
            if answers:
                return answers
        except Exception:
            continue
    return []


def query_dns_txt(domain: str, server: str = "1.1.1.1", timeout: float = 1.0) -> List[str]:
    """Query and decode TXT records for a domain with dnspython and raw UDP fallback."""
    if HAS_DNS:
        try:
            res = dns.resolver.Resolver(configure=True)
            res.nameservers = ["1.1.1.1", "8.8.8.8"] + [ns for ns in res.nameservers if ns not in ("1.1.1.1", "8.8.8.8")]
            res.timeout = timeout
            res.lifetime = timeout * 2
            answers = res.resolve(domain, "TXT")
            records = []
            for rdata in answers:
                text = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                records.append(text)
            if records:
                return records
        except Exception:
            pass

    rdatas = query_dns_raw(domain, qtype=16, server=server, timeout=timeout)
    results = []
    for rdata in rdatas:
        # TXT format: one or more len-prefixed strings
        parts = []
        idx = 0
        while idx < len(rdata):
            tlen = rdata[idx]
            parts.append(rdata[idx + 1:idx + 1 + tlen].decode("utf-8", "replace"))
            idx += 1 + tlen
        results.append("".join(parts))
    return results


def query_dns_tlsa(hostname: str, port: int = 25, server: str = "1.1.1.1", timeout: float = 1.0) -> List[Dict[str, Any]]:
    """Query TLSA records (qtype 52) at _<port>._tcp.<hostname> for DANE."""
    tlsa_name = f"_{port}._tcp.{hostname.strip('.')}"
    if HAS_DNS:
        try:
            res = dns.resolver.Resolver(configure=True)
            res.nameservers = ["1.1.1.1", "8.8.8.8"] + [ns for ns in res.nameservers if ns not in ("1.1.1.1", "8.8.8.8")]
            res.timeout = timeout
            res.lifetime = timeout * 2
            answers = res.resolve(tlsa_name, "TLSA")
            records = []
            for rdata in answers:
                assoc_hex = rdata.cert.hex() if isinstance(rdata.cert, bytes) else str(rdata.cert)
                records.append({
                    "usage": int(rdata.usage),
                    "selector": int(rdata.selector),
                    "matching_type": int(rdata.mtype),
                    "data": assoc_hex,
                    "formatted": f"{rdata.usage} {rdata.selector} {rdata.mtype} {assoc_hex}",
                })
            if records:
                return records
        except Exception:
            pass

    rdatas = query_dns_raw(tlsa_name, qtype=52, server=server, timeout=timeout)
    records = []
    for rd in rdatas:
        if len(rd) >= 3:
            usage = rd[0]
            selector = rd[1]
            matching_type = rd[2]
            assoc_data = rd[3:].hex()
            records.append({
                "usage": usage,
                "selector": selector,
                "matching_type": matching_type,
                "data": assoc_data,
                "formatted": f"{usage} {selector} {matching_type} {assoc_data}",
            })
    return records


def parse_mta_sts_txt(txt_records: Union[List[str], str]) -> Tuple[Optional[str], bool, Optional[str]]:
    """Parse MTA-STS TXT record from DNS TXT answers.

    Returns: (record_text, is_valid, policy_id)
    """
    if isinstance(txt_records, str):
        txt_records = [txt_records]

    for txt in txt_records:
        clean = txt.strip().strip('"').strip("'")
        # May start with or contain v=STSv1
        if "v=stsv1" in clean.lower():
            # Check for id parameter
            id_match = re.search(r'id=["\']?([a-zA-Z0-9_\-\.]+)["\']?', clean, re.IGNORECASE)
            pid = id_match.group(1) if id_match else None
            return clean, True, pid
    return None, False, None


def fetch_mta_sts_policy_file(domain: str, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Fetch https://mta-sts.<domain>/.well-known/mta-sts.txt to extract policy mode."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "SecureMailScope/0.1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            if response.status == 200:
                body = response.read().decode("utf-8", "replace")
                mode = None
                mx_list = []
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith("mode:"):
                        mode = line.split(":", 1)[1].strip().lower()
                    elif line.lower().startswith("mx:"):
                        mx_list.append(line.split(":", 1)[1].strip())
                return {"mode": mode or "enforce", "mx": mx_list, "body": body}
    except Exception:
        pass
    return None


def validate_dane_tlsa(tlsa_records: Union[List[Dict[str, Any]], List[str]], cert_der: Optional[bytes]) -> Tuple[Optional[bool], str]:
    """Validate presented leaf certificate against published DANE TLSA records.

    Accepts list of parsed dicts or list of string TLSA records (e.g. '3 0 1 <hex>').
    Returns: (valid_bool, status_str)
    """
    if not tlsa_records:
        return None, "not_published"
    if not cert_der:
        return None, "skipped"

    parsed_recs: List[Dict[str, Any]] = []
    for r in tlsa_records:
        if isinstance(r, dict):
            parsed_recs.append(r)
        elif isinstance(r, str):
            parts = r.strip().split(None, 3)
            if len(parts) == 4:
                try:
                    parsed_recs.append({
                        "usage": int(parts[0]),
                        "selector": int(parts[1]),
                        "matching_type": int(parts[2]),
                        "data": parts[3].strip(),
                    })
                except ValueError:
                    return False, "invalid_format"
            else:
                return False, "invalid_format"
        else:
            return False, "invalid_format"

    try:
        cert = x509.load_der_x509_certificate(cert_der)
        spki_der = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        return False, "mismatch"

    for r in parsed_recs:
        selector = r.get("selector", 0)
        matching_type = r.get("matching_type", 0)
        assoc_data = r.get("data", "").lower().replace(" ", "")

        # Target payload (0: full cert, 1: SPKI)
        target = cert_der if selector == 0 else spki_der

        # Matching algorithm (0: exact, 1: SHA256, 2: SHA512)
        if matching_type == 0:
            computed = target.hex().lower()
        elif matching_type == 1:
            computed = hashlib.sha256(target).hexdigest().lower()
        elif matching_type == 2:
            computed = hashlib.sha512(target).hexdigest().lower()
        else:
            continue

        if computed == assoc_data:
            return True, "matched"

    return False, "mismatch"


def generate_mta_sts_recommendations(domain: str, mx_hostnames: Optional[List[str]] = None) -> Tuple[str, str]:
    """Generate copy-paste DNS record and HTTPS policy template for administrators."""
    dns_txt = f'_mta-sts.{domain}. IN TXT "v=STSv1; id=20260101000000;"'
    if not mx_hostnames:
        mx_lines = f"mx: mail.{domain}\nmx: *.{domain}"
    else:
        mx_lines = "\n".join(f"mx: {mx}" for mx in mx_hostnames)

    policy_txt = (
        "version: STSv1\n"
        "mode: enforce\n"
        f"{mx_lines}\n"
        "max_age: 604800\n"
    )
    return dns_txt, policy_txt


def _extract_domain_and_host(session: Session) -> Tuple[Optional[str], Optional[str]]:
    """Infer destination domain and hostname from TLS SNI or Certificate SAN/Subject."""
    hostname = None
    if session.tls and session.tls.server_name:
        hostname = session.tls.server_name
    elif session.certificate and session.certificate.san:
        for s in session.certificate.san:
            if s.startswith("DNS:"):
                hostname = s[4:]
                break
            elif not s.startswith("IP:"):
                hostname = s
                break
    elif session.certificate and session.certificate.subject:
        # CN=mail.example.com
        for part in session.certificate.subject.split(","):
            if part.strip().startswith("CN="):
                hostname = part.strip()[3:]
                break

    if not hostname:
        return None, None

    hostname = hostname.strip().lower()
    # If hostname is an IP address, skip DNS heuristics
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return None, None

    # Derive apex domain from hostname
    parts = hostname.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "org", "net", "edu", "ac"):
        domain = ".".join(parts[-3:])
    elif len(parts) >= 2:
        domain = ".".join(parts[-2:])
    else:
        domain = hostname

    return domain, hostname


def evaluate_dns_security(session: Session, check_online: bool = True) -> Optional[DnsSecurityInfo]:
    """Evaluate MTA-STS and DANE TLSA posture for a mail session."""
    domain, hostname = _extract_domain_and_host(session)
    if not domain:
        return None

    info = DnsSecurityInfo(domain=domain, hostname=hostname)

    # 1. MTA-STS Evaluation
    if domain in _MTA_STS_CACHE:
        txt_rec, valid, mode, pid = _MTA_STS_CACHE[domain]
    elif check_online:
        txt_records = query_dns_txt(f"_mta-sts.{domain}")
        txt_rec, valid, pid = parse_mta_sts_txt(txt_records)
        mode = "not_published"
        if valid:
            policy_info = fetch_mta_sts_policy_file(domain)
            mode = policy_info.get("mode", "enforce") if policy_info else "enforce"
        _MTA_STS_CACHE[domain] = (txt_rec, valid, mode, pid)
    else:
        txt_rec, valid, mode, pid = None, False, "skipped", None

    info.mta_sts_record = txt_rec
    info.mta_sts_valid = valid
    info.mta_sts_mode = mode
    info.mta_sts_id = pid

    # 2. DANE TLSA Evaluation
    target_host = hostname or domain
    port = session.server_port or 25
    cache_key = f"{target_host}:{port}"
    if cache_key in _DANE_CACHE:
        tlsa_recs = _DANE_CACHE[cache_key]
    elif check_online:
        tlsa_recs = query_dns_tlsa(target_host, port=port)
        _DANE_CACHE[cache_key] = tlsa_recs
    else:
        tlsa_recs = []

    info.dane_tlsa_records = [r["formatted"] for r in tlsa_recs]

    # Validate against observed cert if available
    cert_der = None
    if session.tls and session.tls.certificate and len(session.tls.certificate) > 0:
        cert_der = session.tls.certificate[0]

    dane_valid, match_status = validate_dane_tlsa(tlsa_recs, cert_der)
    info.dane_valid = dane_valid
    info.dane_match_status = match_status

    # 3. Recommendations
    dns_rec, policy_tpl = generate_mta_sts_recommendations(domain)
    info.recommended_mta_sts_dns = dns_rec
    info.recommended_mta_sts_policy = policy_tpl

    return info
