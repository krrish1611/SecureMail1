"""X.509 certificate extraction, parsing, chain validation, and revocation checking."""

from __future__ import annotations

import datetime as dt
import os
import warnings
from typing import List, Optional, Set

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from .models import CertificateInfo
from .ja4 import compute_ja4x

try:
    from cryptography.x509.verification import PolicyBuilder, Store, DNSName as VerDNSName
    HAVE_VERIFICATION = True
except Exception:  # pragma: no cover
    HAVE_VERIFICATION = False


def load_trust_store(path: Optional[str] = None) -> List[x509.Certificate]:
    """Load a PEM trust store into a list of certificates.

    Defaults to the certifi CA bundle (widely trusted roots).
    """
    if path is None:
        try:
            import certifi
            path = certifi.where()
        except Exception:
            path = "/etc/ssl/certs/ca-certificates.crt"
    certs: List[x509.Certificate] = []
    if not os.path.exists(path):
        return certs
    try:
        with open(path, "rb") as f:
            data = f.read()
        for parsed in _iter_pem_certs(data):
            if parsed is not None:
                certs.append(parsed)
    except Exception:
        pass
    return certs


def _iter_pem_certs(data: bytes) -> List[Optional[x509.Certificate]]:
    certs = []
    try:
        certs = x509.load_pem_x509_certificates(data)
    except Exception:
        # Fallback: split by PEM markers manually
        import re
        for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", data.decode("utf-8", "replace"), re.S):
            try:
                pem = b"-----BEGIN CERTIFICATE-----\n" + m.group(1).strip().encode() + b"\n-----END CERTIFICATE-----\n"
                certs.append(x509.load_pem_x509_certificate(pem))
            except Exception:
                certs.append(None)
    return certs


def _name_str(name) -> Optional[str]:
    if not name or len(name) == 0:
        return None
    try:
        return name.rfc4514_string()
    except Exception:
        try:
            return name.public_bytes().decode("utf-8", "replace")
        except Exception:
            return str(name)


def _derive_key_info(public_key) -> tuple:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        return f"EC ({curve.name})", getattr(curve, "key_size", None)
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", getattr(public_key, "key_size", None)
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(public_key).__name__, None


def parse_certificate(der: bytes) -> Optional[CertificateInfo]:
    """Parse a single DER certificate into a CertificateInfo."""
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    info = CertificateInfo()
    info.subject = _name_str(cert.subject)
    info.issuer = _name_str(cert.issuer)
    try:
        info.not_before = cert.not_valid_before_utc.isoformat()
        info.not_after = cert.not_valid_after_utc.isoformat()
    except Exception:
        info.not_before = str(cert.not_valid_before)
        info.not_after = str(cert.not_valid_after)

    info.serial_number = f"{cert.serial_number:x}"
    algo, size = _derive_key_info(cert.public_key())
    info.public_key_algorithm = algo
    info.key_size = size
    try:
        sig = cert.signature_algorithm_oid
        info.signature_algorithm = sig._name or str(sig)
    except Exception:
        info.signature_algorithm = "unknown"

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        info.san = [str(x) for x in san_ext.value]
    except Exception:
        pass

    try:
        info.self_signed = bool(info.subject and info.subject == info.issuer)
    except Exception:
        pass

    now = dt.datetime.now(dt.timezone.utc)
    try:
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
    except Exception:
        not_after = cert.not_valid_after
        not_before = cert.not_valid_before
    info.expired = now > not_after
    info.not_yet_valid = now < not_before
    if not_after:
        info.days_to_expiry = (not_after - now).days

    # Revocation info from extensions (no network yet).
    info.ocsp_url = _extract_ocsp_url(cert)
    info.crl_urls = _extract_crl_urls(cert)

    info.ja4x = compute_ja4x(cert)

    try:
        info.pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    except Exception:
        pass

    return info


def _extract_ocsp_url(cert: x509.Certificate) -> Optional[str]:
    try:
        aid_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for ad in aid_ext.value:
            if isinstance(ad.access_method, x509.oid.ObjectIdentifier) and \
               ad.access_method.dotted_string == "1.3.6.1.5.5.7.48.1":
                if isinstance(ad.access_location, x509.UniformResourceIdentifier):
                    return ad.access_location.value
    except Exception:
        pass
    return None


def _extract_crl_urls(cert: x509.Certificate) -> List[str]:
    urls = []
    try:
        cd_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for dp in cd_ext.value:
            if dp.full_name is None:
                continue
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
    except Exception:
        pass
    return urls


def _infer_server_name(cert: x509.Certificate) -> Optional[str]:
    """Return the first DNS SAN (or CN) suitable for hostname verification."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for dns in san.get_values_for_type(x509.DNSName):
            if dns and dns != "*":
                return dns
    except Exception:
        pass
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return cn[0].value
    except Exception:
        pass
    return None


def validate_chain(leaf_der: bytes, intermediates: List[bytes],
                   trust_store: Optional[List[x509.Certificate]] = None,
                   leaf_errors: Optional[List[str]] = None) -> tuple:
    """Validate a leaf certificate chain against a trust store.

    Returns (chain_valid, issues, trusted).
    """
    issues = leaf_errors if leaf_errors is not None else []
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as e:
        return False, ["unable to parse certificate"], False
    if trust_store is None:
        trust_store = load_trust_store()
    if not trust_store:
        return None, ["no trust store available"], False

    anchors = list(dict.fromkeys(trust_store))

    # Immediate rejects
    now = dt.datetime.now(dt.timezone.utc)
    try:
        if leaf.not_valid_after_utc < now:
            issues.append("leaf certificate expired")
        if leaf.not_valid_before_utc > now:
            issues.append("leaf certificate not yet valid")
    except Exception:
        pass

    if HAVE_VERIFICATION:
        intermediates_ders = [i for i in intermediates if i]
        try:
            store = Store(anchors)
            name = _infer_server_name(leaf)
            if name is None:
                issues.append("no DNS name in leaf certificate for hostname validation")
                return None, issues, None
            policy = (
                PolicyBuilder()
                .store(store)
                .time(now)
                .max_chain_depth(len(intermediates_ders) + 2)
                .build_server_verifier(VerDNSName(name))
            )
            intermediate_certs = [x509.load_der_x509_certificate(i) for i in intermediates_ders]
            policy.verify(leaf, tuple(intermediate_certs))
            return True, issues, True
        except Exception as e:
            issues.append(f"chain validation failed: {type(e).__name__}")
            return False, issues, False

    # Fallback: manual best-effort single-hop verification
    issues.append("advanced chain validation unavailable")
    return None, issues, None


def check_ocsp(cert_info: CertificateInfo, issuer_der: Optional[bytes],
               timeout: float = 3.0) -> None:
    """Best-effort OCSP revocation check. Never raises; failure -> 'unknown'."""
    cert_info.revocation_method = "ocsp"
    if not cert_info.ocsp_url:
        cert_info.revocation_status = "skipped"
        return
    if issuer_der is None:
        cert_info.revocation_status = "unknown"
        return
    try:
        from cryptography.x509 import ocsp as x509_ocsp
        from cryptography.hazmat.primitives.serialization import encodings
        import urllib.request

        cert = x509.load_der_x509_certificate(_der_from_pem(cert_info.pem))
        issuer = x509.load_der_x509_certificate(issuer_der)
        builder = x509_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        data = req.public_bytes(serialization.Encoding.DER)

        request = urllib.request.Request(
            cert_info.ocsp_url, data=data,
            headers={"Content-Type": "application/ocsp-request"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            resp_bytes = resp.read()
        response = x509_ocsp.load_der_ocsp_response(resp_bytes)
        if response.response_status == x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
            if response.certificate_status == x509_ocsp.OCSPCertStatus.GOOD:
                cert_info.revoked = False
                cert_info.revocation_status = "good"
            elif response.certificate_status == x509_ocsp.OCSPCertStatus.REVOKED:
                cert_info.revoked = True
                cert_info.revocation_status = "revoked"
            else:
                cert_info.revoked = None
                cert_info.revocation_status = "unknown"
        else:
            cert_info.revocation_status = "unknown"
    except Exception:
        cert_info.revocation_status = "unknown"


def _der_from_pem(pem: str) -> bytes:
    """Convert a PEM cert string to DER bytes."""
    import base64
    parts = pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
    return base64.b64decode(parts.encode())


def validate_certificates(certs_der: List[bytes],
                          trust_store: Optional[List[x509.Certificate]] = None) -> tuple:
    """Parse a list of DER certs (leaf first), validate chain, and attempt revocation.

    Returns (parsed, leaf, chain_valid, issues).
    """
    parsed = []
    for der in certs_der:
        info = parse_certificate(der)
        if info is not None:
            parsed.append(info)
    leaf = parsed[0] if parsed else None
    if not leaf:
        return parsed, None, None, ["no certificate data"]

    leaf_issues = []
    if leaf.self_signed:
        chain_valid = False
        leaf_issues.append("self-signed certificate")
        trusted = False
    else:
        leaf_der = _der_from_pem(leaf.pem)
        intermediates = certs_der[1:]
        chain_valid, leaf_issues, trusted = validate_chain(leaf_der, intermediates,
                                                           trust_store=trust_store,
                                                           leaf_errors=leaf_issues)
    leaf.chain_valid = chain_valid if chain_valid is not None else False
    leaf.trusted = bool(trusted)
    leaf.chain_issues = leaf_issues

    # Best-effort OCSP revocation on the leaf (offline-safe).
    if hasattr(leaf, "ocsp_url") and leaf.ocsp_url and len(certs_der) > 1:
        check_ocsp(leaf, certs_der[1])
    else:
        leaf.revocation_status = "skipped"

    return parsed, leaf, chain_valid, leaf_issues
