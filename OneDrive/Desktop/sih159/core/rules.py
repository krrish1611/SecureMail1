"""Cryptographic weakness detection rule engine.

Evaluates a session's TLS/cert/STARTTLS attributes against a curated set of
rules covering deprecated TLS versions, weak cipher suites, insecure key
exchange, weak public keys, certificate problems, and STARTTLS issues.
Each rule emits a Finding with severity, CWE/CVE mapping, and remediation.
"""

from __future__ import annotations

from typing import Dict, List

from .models import Finding, Severity, Session, CertificateInfo
from .pqc import assess_pqc_readiness
from .attribution import attribute_session

WEAK_CIPHER_MARKERS = {
    "RC4": (Severity.CRITICAL, "cipher.rc4", "CWE-327", "CVE-2015-2808", "RC4 cipher is broken for all uses; disable it."),
    "3DES": (Severity.HIGH, "cipher.3des", "CWE-327", "CVE-2016-2183", "3DES (DES-EDE3) provides only ~112 bits of security (Sweet32)."),
    "DES": (Severity.CRITICAL, "cipher.des", "CWE-327", "CVE-2016-2183", "Single DES is trivially brute-forcible."),
    "EXPORT": (Severity.CRITICAL, "cipher.export", "CWE-327", "CVE-2015-0204", "Export-grade cipher suite enables FREAK downgrade."),
    "NULL": (Severity.CRITICAL, "cipher.null", "CWE-319", "CVE-2015-4000", "NULL encryption provides no confidentiality."),
    "CBC_SHA\b": (Severity.LOW, "cipher.cbc_sha1", "CWE-327", "CVE-2016-2183", "CBC with SHA1 (non-AEAD) is vulnerable to padding oracle issues."),
}

WEAK_CIPHER_SUFFIX = ("_CBC_SHA\b", "_CBC_SHA256", "_CBC_SHA384")
DEPRECATED_HASH_TLS13 = False


class RuleEngine:
    """Applies security rules to sessions and collects findings."""

    def __init__(self) -> None:
        self.rules_run = 0

    def evaluate_tls_version(self, session: Session, findings: List[Finding]) -> None:
        tls = session.tls
        if not tls or not tls.version:
            return
        ver = tls.version
        if ver in ("SSLv2", "SSLv3"):
            findings.append(self._finding(
                id="tls.ssl3", title="Deprecated/insecure SSL/TLS version in use",
                description=f"The session negotiated {ver}, which is critically deprecated "
                            "and vulnerable to downgrade and padding attacks (e.g. POODLE).",
                category="tls.version", severity=Severity.CRITICAL,
                cwe="CWE-326", cve="CVE-2014-3566",
                rec="Disable SSLv2/SSLv3 in the mail server; require TLS 1.2 or higher.",
            ))
        elif ver == "TLSv1.0":
            findings.append(self._finding(
                id="tls.10", title="Obsolete TLS 1.0 negotiated",
                description="TLS 1.0 is deprecated and vulnerable to BEAST and RC4-based attacks.",
                category="tls.version", severity=Severity.HIGH,
                cwe="CWE-326", cve="CVE-2011-3389",
                rec="Disable TLS 1.0 on the server; require TLS 1.2+.",
            ))
        elif ver == "TLSv1.1":
            findings.append(self._finding(
                id="tls.11", title="Obsolete TLS 1.1 negotiated",
                description="TLS 1.1 is deprecated per RFC 8996 and should not be used.",
                category="tls.version", severity=Severity.MEDIUM,
                cwe="CWE-326", cve=None,
                rec="Disable TLS 1.1; require TLS 1.2+.",
            ))

        # Offered (client) weak versions indicate downgrade risk.
        weak_offered = [v for v in tls.offered_versions if v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]
        if not tls.version and weak_offered:
            findings.append(self._finding(
                id="tls.weak_offered", title="Server offers only deprecated TLS versions",
                description=f"The server offered insecure versions: {', '.join(sorted(set(weak_offered)))}.",
                category="tls.version", severity=Severity.HIGH, cwe="CWE-326",
                rec="Configure the server to support TLS 1.2 and TLS 1.3 only.",
            ))

    def evaluate_cipher(self, session: Session, findings: List[Finding]) -> None:
        tls = session.tls
        if not tls or not tls.cipher_suite:
            return
        cs = tls.cipher_suite
        upper = cs.upper()
        severity = None
        for marker, (sev, fid, cwe, cve, desc) in WEAK_CIPHER_MARKERS.items():
            if marker in upper and marker != "CBC_SHA\b":
                severity = sev
                findings.append(self._finding(
                    id=fid, title="Weak cipher suite in use",
                    description=f"{cs} uses {marker}: {desc}",
                    category="tls.cipher", severity=sev, cwe=cwe, cve=cve,
                    rec="Remove weak cipher suites from the server's TLS configuration.",
                ))
        # Non-AEAD CBC suites without AES-GCM/CHACHA -> medium
        if not severity and ("CBC" in upper and "GCM" not in upper and "CHACHA" not in upper):
            findings.append(self._finding(
                id="tls.cipher.cbc_sha1", title="Non-AEAD CBC cipher negotiated",
                description=f"{cs} uses CBC mode without authenticated encryption.",
                category="tls.cipher", severity=Severity.MEDIUM, cwe="CWE-327", cve="CVE-2016-2183",
                rec="Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
            ))

    def evaluate_key_exchange(self, session: Session, findings: List[Finding]) -> None:
        tls = session.tls
        if not tls:
            return
        ke = tls.key_exchange
        if not ke:
            return
        if "RSA (static)" in ke or ke == "ECDH (static)":
            findings.append(self._finding(
                id="tls.keyex.no_fs", title="No forward secrecy (static key exchange)",
                description=f"The session used {ke} key exchange, which does not provide "
                            "forward secrecy. A compromised server key could decrypt past traffic.",
                category="tls.keyexchange", severity=Severity.HIGH, cwe="CWE-327",
                cve="CVE-2015-4000", rec="Enable ephemeral key exchange (ECDHE/DHE) with forward secrecy.",
            ))
        if tls.key_exchange_group and ("ffdhe3072" in tls.key_exchange_group or "ffdhe2048" in tls.key_exchange_group):
            meh = [g for g in (tls.key_exchange_group,) if "ffdhe" in g]
            if meh and "ffdhe2048" in meh[0]:
                findings.append(self._finding(
                    id="tls.keyex.dh_weak", title="Weak Diffie-Hellman modulus (2048-bit)",
                    description="The negotiated DH group is only 2048-bit (Logjam risk if <2048).",
                    category="tls.keyexchange", severity=Severity.MEDIUM, cwe="CWE-326", cve="CVE-2015-4000",
                    rec="Use DH groups of at least 3072 bits or prefer ECDHE.",
                ))

    def evaluate_certificate(self, session: Session, findings: List[Finding]) -> None:
        cert = session.certificate
        if not cert:
            return
        if cert.expired:
            findings.append(self._finding(
                id="cert.expired", title="Expired certificate",
                description=f"The server certificate (subject: {cert.subject}) expired "
                            f"on {cert.not_after}.",
                category="certificate", severity=Severity.HIGH, cwe="CWE-298",
                rec="Renew and replace the expired certificate before re-enabling public access.",
            ))
        if cert.not_yet_valid:
            findings.append(self._finding(
                id="cert.not_yet_valid", title="Certificate not yet valid",
                description="The certificate's validity period has not started.",
                category="certificate", severity=Severity.HIGH, cwe="CWE-298",
                rec="Check the system clock and replace the certificate.",
            ))
        if cert.days_to_expiry is not None and cert.days_to_expiry < 30:
            findings.append(self._finding(
                id="cert.will_expire", title="Certificate expiring soon",
                description=f"Certificate expires in {cert.days_to_expiry} day(s).",
                category="certificate", severity=Severity.MEDIUM, cwe="CWE-298",
                rec="Schedule certificate renewal within 30 days.",
            ))
        if cert.self_signed:
            findings.append(self._finding(
                id="cert.self_signed", title="Self-signed certificate",
                description="The server presented a self-signed certificate, so clients cannot verify identity.",
                category="certificate", severity=Severity.MEDIUM, cwe="CWE-295",
                rec="Obtain a certificate from a trusted public CA.",
            ))
        if cert.chain_valid is False and not cert.expired:
            findings.append(self._finding(
                id="cert.chain_invalid", title="Invalid certificate chain",
                description="The certificate chain could not be validated to a trusted root.",
                category="certificate", severity=Severity.MEDIUM, cwe="CWE-295",
                rec="Install the full certificate chain on the server.",
            ))
        if cert.trusted is False and not cert.self_signed:
            findings.append(self._finding(
                id="cert.untrusted", title="Certificate not trusted by a public CA",
                description="The presented certificate does not chain to a trusted root CA, "
                            "so clients cannot cryptographically verify the server's identity.",
                category="certificate", severity=Severity.HIGH, cwe="CWE-295",
                rec="Obtain a certificate from a recognized public (or internal corporate) CA.",
            ))
        if cert.revoked:
            findings.append(self._finding(
                id="cert.revoked", title="Certificate is revoked",
                description="The server certificate has been revoked via "
                            f"{cert.revocation_method or 'status check'}, indicating the private key "
                            "may be compromised.",
                category="certificate", severity=Severity.CRITICAL, cwe="CWE-295",
                rec="Immediately revoke further use, replace the certificate, and rotate the key.",
            ))
        # Public key strength
        if cert.public_key_algorithm == "RSA" and cert.key_size and cert.key_size < 2048:
            findings.append(self._finding(
                id="cert.weak_pubkey", title="Weak RSA public key",
                description=f"RSA key size is only {cert.key_size} bits (below the 2048-bit minimum).",
                category="certificate", severity=Severity.HIGH, cwe="CWE-326",
                rec="Reissue the certificate with a 2048-bit (or larger) RSA key.",
            ))
        elif cert.public_key_algorithm and "EC" in cert.public_key_algorithm and cert.key_size and cert.key_size < 256:
            findings.append(self._finding(
                id="cert.weak_ec", title="Weak elliptic-curve key",
                description=f"Elliptic-curve key strength is only {cert.key_size} bits.",
                category="certificate", severity=Severity.HIGH, cwe="CWE-326",
                rec="Reissue the certificate with at least a 256-bit curve (e.g. P-256).",
            ))
        if cert.signature_algorithm and "SHA1" in cert.signature_algorithm.upper():
            findings.append(self._finding(
                id="cert.sha1_sig", title="SHA-1 signature algorithm",
                description="Certificate uses the SHA-1 signature algorithm, which is broken for collision attacks.",
                category="certificate", severity=Severity.MEDIUM, cwe="CWE-328", cve="CVE-2017-15361",
                rec="Reissue the certificate signed with SHA-256 or stronger.",
            ))
        if cert.key_size and cert.days_to_expiry is not None and cert.days_to_expiry > 398:
            findings.append(self._finding(
                id="cert.long_validity", title="Certificate validity exceeds 13 months (398 days)",
                description="Publicly trusted certificates should not be valid for more than 398 days per CA/B Forum.",
                category="certificate", severity=Severity.INFO, cwe="CWE-298",
                rec="Renew certificates within 398 days.",
            ))

    def evaluate_starttls(self, session: Session, findings: List[Finding]) -> None:
        if session.protocol not in ("smtp", "imap", "pop3"):
            return
        if session.plaintext and not session.starttls:
            findings.append(self._finding(
                id="starttls.missing", title="No encryption (STARTTLS not used)",
                description="The email session exchanged data in plaintext without STARTTLS.",
                category="starttls", severity=Severity.HIGH, cwe="CWE-319",
                rec="Require STARTTLS and reject plaintext sessions.",
            ))
        if session.credentials_plaintext:
            findings.append(self._finding(
                id="starttls.plaintext_creds", title="Credentials sent in plaintext",
                description=f"Authentication credentials ({session.auth_command_observed or 'unknown'}) "
                            "were observed before the TLS upgrade.",
                category="starttls", severity=Severity.CRITICAL, cwe="CWE-319",
                rec="Never send credentials before the TLS handshake; enforce STARTTLS-before-AUTH.",
            ))
        if session.starttls_stripped:
            findings.append(self._finding(
                id="starttls.stripped", title="STARTTLS downgrade detected (stripped)",
                description="The server accepted STARTTLS but no TLS handshake followed, or the "
                            "upgrade was stripped, enabling man-in-the-middle interception.",
                category="starttls", severity=Severity.CRITICAL, cwe="CWE-757",
                rec="Install a valid certificate and verify TLS actually activates after STARTTLS.",
            ))

    def evaluate_dns_security(self, session: Session, findings: List[Finding]) -> None:
        dns_sec = session.dns_security
        if not dns_sec or not dns_sec.domain:
            return

        # MTA-STS evaluation
        if dns_sec.mta_sts_valid:
            if dns_sec.mta_sts_mode == "enforce":
                findings.append(self._finding(
                    id="mta_sts.enforce",
                    title=f"MTA-STS downgrade protection active ({dns_sec.domain})",
                    description=f"Destination domain {dns_sec.domain} enforces MTA-STS (id={dns_sec.mta_sts_id or 'unknown'}), "
                                "preventing active Man-in-the-Middle STARTTLS downgrade attacks.",
                    category="downgrade_protection",
                    severity=Severity.INFO,
                    cwe="CWE-757",
                    rec="Maintain MTA-STS policy renewals and monitor TLS-RPT reports (RFC 8461).",
                ))
            elif dns_sec.mta_sts_mode == "testing":
                findings.append(self._finding(
                    id="mta_sts.testing",
                    title=f"MTA-STS in testing mode ({dns_sec.domain})",
                    description=f"Destination domain {dns_sec.domain} publishes an MTA-STS policy in 'testing' mode. "
                                "Mail servers will not reject cleartext fallbacks if an adversary strips STARTTLS.",
                    category="downgrade_protection",
                    severity=Severity.LOW,
                    cwe="CWE-757",
                    rec="Switch MTA-STS policy mode from 'testing' to 'enforce' once mail delivery is validated.",
                ))
        else:
            findings.append(self._finding(
                id="mta_sts.missing",
                title=f"MTA-STS downgrade protection not published ({dns_sec.domain})",
                description=f"Domain {dns_sec.domain} does not publish an MTA-STS DNS record (_mta-sts.{dns_sec.domain}). "
                            "Without MTA-STS, opportunistic STARTTLS is vulnerable to silent active stripping attacks.",
                category="downgrade_protection",
                severity=Severity.LOW,
                cwe="CWE-757",
                rec=f"Publish a TXT record at _mta-sts.{dns_sec.domain} ('v=STSv1; id=...') and an HTTPS policy file (mode: enforce).",
            ))

        # DANE TLSA evaluation
        if dns_sec.dane_tlsa_records:
            if dns_sec.dane_valid is True:
                findings.append(self._finding(
                    id="dane.verified",
                    title=f"DANE TLSA cryptographically validated ({dns_sec.hostname})",
                    description=f"The presented certificate/key matches published DNSSEC-secured DANE TLSA records for {dns_sec.hostname}.",
                    category="downgrade_protection",
                    severity=Severity.INFO,
                    cwe="CWE-295",
                    rec="Ensure DNSSEC and TLSA records remain synchronized upon certificate renewal (RFC 7672).",
                ))
            elif dns_sec.dane_match_status == "mismatch":
                findings.append(self._finding(
                    id="dane.mismatch",
                    title=f"DANE TLSA record mismatch ({dns_sec.hostname})",
                    description=f"Presented TLS certificate does not match the published DANE TLSA record for {dns_sec.hostname}. "
                                "This may indicate an active Man-in-the-Middle attack or a misconfigured certificate roll.",
                    category="downgrade_protection",
                    severity=Severity.HIGH,
                    cwe="CWE-295",
                    rec="Verify server certificate matches published DNS TLSA association parameters immediately.",
                ))

    def evaluate_pqc(self, session: Session, findings: List[Finding]) -> None:
        if not session.pqc:
            tls = session.tls
            cert = session.certificate
            session.pqc = assess_pqc_readiness(
                tls_version=tls.version if tls else None,
                key_exchange=tls.key_exchange if tls else None,
                key_exchange_group=tls.key_exchange_group if tls else None,
                cipher_suite=tls.cipher_suite if tls else None,
                cert_sig_alg=cert.signature_algorithm if cert else None,
                is_encrypted=session.encrypted,
            )
        pqc = session.pqc
        if pqc.pqc_status == "QUANTUM_RESISTANT":
            findings.append(self._finding(
                id="pqc.hybrid_active",
                title=f"Post-quantum hybrid key exchange active ({pqc.kem_algorithm})",
                description=f"Session negotiated a quantum-resistant hybrid KEM ({pqc.kem_algorithm} + {pqc.classical_algorithm}) "
                            f"compliant with {', '.join(pqc.standard_compliance) or 'NIST FIPS 203'}.",
                category="post_quantum",
                severity=Severity.INFO,
                cwe="CWE-326",
                rec="Maintain hybrid post-quantum deployment per NIST FIPS 203 standards.",
            ))
        elif pqc.hndl_risk == "CRITICAL" and session.encrypted:
            findings.append(self._finding(
                id="pqc.harvest_decrypt_critical",
                title="Critical Harvest-Now-Decrypt-Later (HNDL) quantum exposure",
                description="Traffic uses static key exchange or obsolete TLS versions lacking forward secrecy, allowing "
                            "retrospective decryption by a cryptanalytically relevant quantum computer (CRQC).",
                category="post_quantum",
                severity=Severity.HIGH,
                cwe="CWE-327",
                rec="Upgrade to TLS 1.3 with forward secrecy and hybrid post-quantum key exchange (X25519MLKEM768).",
            ))

    def evaluate_attribution(self, session: Session, findings: List[Finding]) -> None:
        if not session.attribution:
            session.attribution = attribute_session(session)
        attr = session.attribution
        if attr.masquerading_detected:
            findings.append(self._finding(
                id="threat.masquerading",
                title="Client fingerprint masquerading / spoofing detected",
                description=attr.masquerading_details or "Client identity claim contradicts JA4 cryptographic fingerprint.",
                category="threat_attribution",
                severity=Severity.CRITICAL,
                cwe="CWE-290",
                rec="Investigate client IP for unauthorized mail automation or credential compromise.",
            ))
        elif attr.is_known_threat:
            findings.append(self._finding(
                id="threat.known_scanner",
                title=f"Suspicious automated scanner or bot detected ({attr.client_name})",
                description=f"Client JA4 fingerprint indicates automated scanning or adversarial tooling ({attr.client_name}).",
                category="threat_attribution",
                severity=Severity.HIGH,
                cwe="CWE-200",
                rec="Review firewall and MTA access rules for source IP address.",
            ))

    def _finding(self, **kwargs):
        if "rec" in kwargs:
            kwargs["recommendation"] = kwargs.pop("rec")
        return Finding(**kwargs)

    def evaluate_all(self, session: Session) -> List[Finding]:
        findings: List[Finding] = []
        self.evaluate_tls_version(session, findings)
        self.evaluate_cipher(session, findings)
        self.evaluate_key_exchange(session, findings)
        self.evaluate_certificate(session, findings)
        self.evaluate_starttls(session, findings)
        self.evaluate_dns_security(session, findings)
        self.evaluate_pqc(session, findings)
        self.evaluate_attribution(session, findings)
        session.findings = findings
        return findings

