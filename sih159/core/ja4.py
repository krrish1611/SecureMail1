"""JA4+ cryptographic fingerprinting suite (JA4, JA4S, JA4X).

Implements the FoxIO JA4+ open standards for network security forensics:
- JA4: TLS Client Hello fingerprinting (replaces JA3 with sorted, drift-resistant hashes)
- JA4S: TLS Server Hello response fingerprinting
- JA4X: X.509 Digital Certificate structural fingerprinting
"""

from __future__ import annotations

import hashlib
from typing import Any, List, Optional, Union
from cryptography import x509

# RFC 8701 GREASE values table
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

TLS_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


def is_grease(val: int) -> bool:
    """Return True if integer value is an RFC 8701 GREASE value."""
    if val in GREASE_VALUES:
        return True
    return ((val & 0x0F0F) == 0x0A0A) and (((val >> 8) & 0xFF) == (val & 0xFF))


def _sha256_12(s: str) -> str:
    """Compute lower-case SHA256 hash truncated to first 12 characters."""
    if not s:
        return "000000000000"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12].lower()


def _format_alpn(alpn_val: Optional[str]) -> str:
    """Format 2-character ALPN token (first & last alphanumeric char or 00)."""
    if not alpn_val or len(alpn_val) < 1:
        return "00"
    clean = "".join(c for c in alpn_val if c.isalnum())
    if not clean:
        return "00"
    if len(clean) == 1:
        return f"{clean[0]}{clean[0]}"
    return f"{clean[0]}{clean[-1]}"


def compute_ja4(
    ciphers: List[int],
    extensions: List[int],
    protocol_version: int,
    supported_versions: Optional[List[int]] = None,
    sni: Optional[str] = None,
    alpn: Optional[str] = None,
    sig_algs: Optional[List[int]] = None,
    transport: str = "t",
) -> str:
    """Compute JA4 client fingerprint from TLS ClientHello parameters.

    Format: {part_a}_{part_b}_{part_c}
      part_a (10 chars): [transport][version][sni][cipher_count][ext_count][alpn]
      part_b (12 chars): sha256(sorted non-grease ciphers hex)
      part_c (12 chars): sha256(sorted non-grease exts hex _ sigalgs hex)
    """
    # 1. Determine Version
    ver_str = "00"
    if supported_versions:
        # Highest non-GREASE version
        valid_vers = [v for v in supported_versions if not is_grease(v)]
        if valid_vers:
            highest_ver = max(valid_vers)
            ver_str = TLS_VERSION_CODES.get(highest_ver, "00")
    if ver_str == "00":
        ver_str = TLS_VERSION_CODES.get(protocol_version, "00")

    # 2. SNI Indicator ('d' for domain, 'i' for IP / none)
    sni_str = "d" if (sni and len(sni) > 0) else "i"

    # 3. Filter ciphers (exclude GREASE)
    clean_ciphers = [c for c in ciphers if not is_grease(c)]
    cipher_count = min(len(clean_ciphers), 99)

    # 4. Filter extensions (exclude GREASE, SNI 0x0000, and ALPN 0x0010)
    clean_exts = [
        e for e in extensions
        if not is_grease(e) and e not in (0x0000, 0x0010)
    ]
    ext_count = min(len(clean_exts), 99)

    # 5. ALPN token
    alpn_token = _format_alpn(alpn)

    # Part A
    part_a = f"{transport}{ver_str}{sni_str}{cipher_count:02d}{ext_count:02d}{alpn_token}"

    # Part B: Sorted 4-char hex ciphers
    if clean_ciphers:
        sorted_ciphers_hex = sorted(f"{c:04x}" for c in clean_ciphers)
        ciphers_str = ",".join(sorted_ciphers_hex)
        part_b = _sha256_12(ciphers_str)
    else:
        part_b = "000000000000"

    # Part C: Sorted 4-char hex extensions + signature algorithms
    clean_sig_algs = [s for s in (sig_algs or []) if not is_grease(s)]
    sorted_exts_hex = sorted(f"{e:04x}" for e in clean_exts)
    ext_str = ",".join(sorted_exts_hex)

    if clean_sig_algs:
        sig_str = ",".join(f"{s:04x}" for s in clean_sig_algs)
        combined_c = f"{ext_str}_{sig_str}"
    else:
        combined_c = ext_str

    if combined_c and combined_c != "_":
        part_c = _sha256_12(combined_c)
    else:
        part_c = "000000000000"

    return f"{part_a}_{part_b}_{part_c}"


def compute_ja4s(
    cipher: int,
    extensions: List[int],
    negotiated_version: int,
    alpn: Optional[str] = None,
    transport: str = "t",
) -> str:
    """Compute JA4S server fingerprint from TLS ServerHello parameters.

    Format: {part_a}_{part_b}_{part_c}
      part_a (7 chars): [transport][version][ext_count][alpn]
      part_b (4 chars): cipher hex (0000 if none)
      part_c (12 chars): sha256(sorted non-grease exts hex, excluding ALPN)
    """
    ver_str = TLS_VERSION_CODES.get(negotiated_version, "00")
    clean_exts = [
        e for e in extensions
        if not is_grease(e) and e != 0x0010
    ]
    ext_count = min(len(clean_exts), 99)
    alpn_token = _format_alpn(alpn)

    part_a = f"{transport}{ver_str}{ext_count:02d}{alpn_token}"
    part_b = f"{cipher:04x}" if cipher else "0000"

    if clean_exts:
        sorted_exts_hex = sorted(f"{e:04x}" for e in clean_exts)
        part_c = _sha256_12(",".join(sorted_exts_hex))
    else:
        part_c = "000000000000"

    return f"{part_a}_{part_b}_{part_c}"


def compute_ja4x(cert: Union[x509.Certificate, bytes]) -> str:
    """Compute JA4X X.509 certificate fingerprint.

    Format: {issuer_hash}_{subject_hash}_{extensions_hash}
      Each part is 12 characters truncated SHA-256 of the respective component.
    """
    if isinstance(cert, bytes):
        try:
            cert = x509.load_der_x509_certificate(cert)
        except Exception:
            try:
                cert = x509.load_pem_x509_certificate(cert)
            except Exception:
                return "000000000000_000000000000_000000000000"

    # 1. Issuer RDN attributes
    issuer_items = []
    try:
        for rdn in cert.issuer:
            issuer_items.append(f"{rdn.oid.dotted_string}={rdn.value}")
    except Exception:
        pass
    issuer_str = ",".join(issuer_items)
    issuer_hash = _sha256_12(issuer_str)

    # 2. Subject RDN attributes
    subject_items = []
    try:
        for rdn in cert.subject:
            subject_items.append(f"{rdn.oid.dotted_string}={rdn.value}")
    except Exception:
        pass
    subject_str = ",".join(subject_items)
    subject_hash = _sha256_12(subject_str)

    # 3. Certificate Extensions OIDs
    ext_items = []
    try:
        for ext in cert.extensions:
            ext_items.append(ext.oid.dotted_string)
    except Exception:
        pass
    ext_str = ",".join(ext_items)
    ext_hash = _sha256_12(ext_str)

    return f"{issuer_hash}_{subject_hash}_{ext_hash}"
