"""Application-layer email protocol identification and STARTTLS detection."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Banners/markers used to identify each protocol from plaintext.
SMTP_PATTERNS = [rb"220 .*ESMTP", rb"220 .*SMTP", rb"^EHLO ", rb"^HELO ", rb"^MAIL FROM:"]
IMAP_PATTERNS = [rb"^\* OK", rb"^CAPABILITY ", rb"^A[0-9]+ LOGIN ", rb"IMAP4rev1"]
POP3_PATTERNS = [rb"^\+OK.*POP3", rb"^USER ", rb"^PASS ", rb"^STAT\r\n", rb"^RETR "]


class ProtocolDetector:
    """Detects email protocols from reassembled stream bytes and STARTTLS state."""

    def __init__(self) -> None:
        # regex bytes
        self.smtp = [re.compile(p) for p in SMTP_PATTERNS]
        self.imap = [re.compile(p) for p in IMAP_PATTERNS]
        self.pop3 = [re.compile(p) for p in POP3_PATTERNS]

    def detect(self, banner_bytes: bytes, client_bytes: bytes) -> Optional[str]:
        """Detect protocol from server banner and client bytes."""
        combined = banner_bytes[:2048] + client_bytes[:2048]
        scores = {"smtp": 0, "imap": 0, "pop3": 0}
        if self._match_any(self.smtp, combined):
            scores["smtp"] += 3
        if self._match_any(self.imap, combined):
            scores["imap"] += 3
        if self._match_any(self.pop3, combined):
            scores["pop3"] += 3
        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else None

    def _match_any(self, patterns: List[re.Pattern], data: bytes) -> bool:
        for p in patterns:
            if p.search(data):
                return True
        return False


# STARTTLS command tokens per protocol.
STARTTLS_CMDS = {
    "smtp": b"STARTTLS",
    "imap": b"STARTTLS",
    "pop3": b"STLS",
}

# Responses that indicate the server accepts STARTTLS and is about to upgrade.
ACCEPT_TOKENS = {
    "smtp": [b"220", b"250"],
    "imap": [b"OK"],
    "pop3": [b"+OK"],
}


def detect_starttls(protocol: str, server_data: bytes, client_data: bytes) -> dict:
    """Analyze the plaintext window for STARTTLS negotiation.

    Returns a dict with:
        requested: STARTTLS command was sent
        upgraded: encryption actually began (TLS handshake follows the 220/OK)
        stripped: STARTTLS accepted but no TLS handshake followed (downgrade)
        tls_start_index: byte offset in stream where TLS handshake begins
    """
    cmd = STARTTLS_CMDS.get(protocol)
    result = {
        "requested": False,
        "upgraded": False,
        "stripped": False,
        "tls_start_index_client": None,
        "tls_start_index_server": None,
    }
    if not cmd:
        return result

    idx = client_data.find(cmd)
    if idx >= 0:
        result["requested"] = True
        result["tls_start_index_client"] = idx + len(cmd)

    if not result["requested"]:
        return result

    accept_tokens = ACCEPT_TOKENS.get(protocol, [])
    accepted = any(tok in server_data[:idx + 64] for tok in accept_tokens)
    if not accepted:
        return result

    # After STARTTLS and acceptance, TLS ClientHello begins with 0x16 0x03.
    post = server_data[idx:idx + 256]
    handshake_marker = b"\x16\x03"
    if handshake_marker in post:
        result["upgraded"] = True
        result["tls_start_index_server"] = idx + post.find(handshake_marker)
    else:
        # Server accepted but no TLS upgrade detected -> possible strip.
        result["stripped"] = True

    return result


def detect_credentials_plaintext(protocol: str, data: bytes, starttls_start: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """Detect if credentials/auth were sent in the plaintext window.

    Only considers data before the STARTTLS upgrade point (if provided).
    Returns (found, auth_command).
    """
    if starttls_start is not None:
        data = data[:starttls_start]

    if protocol == "smtp":
        # AUTH LOGIN / AUTH PLAIN (standalone or with an initial base64 response)
        if re.search(rb"AUTH\s+LOGIN(?:\s|$)", data):
            return True, "AUTH LOGIN"
        if re.search(rb"AUTH\s+PLAIN(?:\s|$)", data):
            return True, "AUTH PLAIN"
        return (b"Authentication successful" not in data and False, None)
    elif protocol == "imap":
        m = re.search(rb"LOGIN\s+", data)
        if m:
            return True, "LOGIN"
        return False, None
    elif protocol == "pop3":
        m = re.search(rb"^USER ", data, re.MULTILINE)
        if m:
            return True, "USER/PASS"
        return False, None
    return False, None
