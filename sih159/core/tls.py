"""TLS record and handshake parsing for passive analysis.

Parses TLS records from reconstructed streams, extracts handshake details
(version, cipher suites, key exchange, extensions), computes JA3, and
extracts X.509 certificates from the Certificate handshake messages.
"""

from __future__ import annotations

import hashlib
from typing import List, Optional, Tuple

from .models import TLSInfo, CertificateInfo
from .ja4 import compute_ja4, compute_ja4s

# TLS record content types
CHANGE_CIPHER_SPEC = 20
ALERT = 21
HANDSHAKE = 22
APPLICATION_DATA = 23

# TLS handshake message types
HELLO_REQUEST = 0
CLIENT_HELLO = 1
SERVER_HELLO = 2
NEW_SESSION_TICKET = 4
ENCRYPTED_EXTENSIONS = 8
CERTIFICATE = 11
SERVER_KEY_EXCHANGE = 12
SERVER_HELLO_DONE = 14
CERTIFICATE_VERIFY = 15
CLIENT_KEY_EXCHANGE = 16
FINISHED = 20
KEY_UPDATE = 24

TLS_CONTENT_KEYS = {
    (0x00, 0x2F): "TLS_RSA_WITH_AES_128_CBC_SHA",
    (0x00, 0x35): "TLS_RSA_WITH_AES_256_CBC_SHA",
    (0x00, 0x3C): "TLS_RSA_WITH_AES_128_CBC_SHA256",
    (0x00, 0x9C): "TLS_RSA_WITH_AES_128_GCM_SHA256",
    (0x00, 0x9D): "TLS_RSA_WITH_AES_256_GCM_SHA384",
    (0x00, 0x04): "TLS_RSA_WITH_RC4_128_MD5",
    (0x00, 0x05): "TLS_RSA_WITH_RC4_128_SHA",
    (0x00, 0x0A): "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    (0x00, 0x03): "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    (0x00, 0x09): "TLS_RSA_WITH_DES_CBC_SHA",
    (0x00, 0x13): "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    (0x00, 0x16): "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    (0xC0, 0x13): "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    (0xC0, 0x14): "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    (0xC0, 0x02): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    (0xC0, 0x0A): "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    (0xC0, 0x27): "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    (0xC0, 0x28): "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    (0xC0, 0x2B): "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    (0xC0, 0x2C): "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    (0xC0, 0x2F): "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    (0xC0, 0x30): "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    (0xC0, 0x09): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    (0xC0, 0x09): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    # TLS 1.3
    (0x13, 0x01): "TLS_AES_128_GCM_SHA256",
    (0x13, 0x02): "TLS_AES_256_GCM_SHA384",
    (0x13, 0x03): "TLS_CHACHA20_POLY1305_SHA256",
    # PSK / DHE
    (0x00, 0x3D): "TLS_RSA_WITH_AES_256_CBC_SHA256",
    (0xC0, 0x23): "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
}

# TLS 1.3 named groups -> key exchange
NAMED_GROUPS = {
    0x001d: "x25519",
    0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}

# Signature algorithm -> human name
SIG_ALGS = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pss_rsae_sha256",
    0x0403: "rsa_pss_rsae_sha384",
    0x0501: "rsa_pss_pss_sha256",
    0x0601: "ed25519",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0807: "ed25519",
    0x0202: "rsa_pkcs1_sha256",
    0x0203: "ecdsa_secp256r1_sha256",
}

VERSION_NAMES = {
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
    0x0002: "SSLv2",
    0x0300: "SSLv3",
}


def _read_u8(b: bytes, off: int) -> Tuple[int, int]:
    return b[off], off + 1


def _read_u16(b: bytes, off: int) -> Tuple[int, int]:
    return (b[off] << 8) | b[off + 1], off + 2


def _read_u24(b: bytes, off: int) -> Tuple[int, int]:
    return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2], off + 3


class TLSRecordParser:
    """Parses a stream of TLS records into handshake data structures."""

    def __init__(self) -> None:
        self.records: List[dict] = []
        self.client_hello: Optional[dict] = None
        self.server_hello: Optional[dict] = None
        self.encrypted_extensions: Optional[dict] = None
        self.certificates: List[bytes] = []   # raw DER certs, in order
        self.cipher_suite: str = None
        self.cipher_hex: str = None
        self.version: str = None
        self.version_rank: int = 0
        self.key_exchange: str = None
        self.key_exchange_group: str = None
        self.signature_algorithm: str = None
        self.sni: str = None
        self.offered_versions: List[str] = []
        self.offered_ciphers: List[str] = []
        self.extensions: List[str] = []
        self.ja3: Optional[str] = None
        self.ja4: Optional[str] = None
        self.ja4s: Optional[str] = None
        self.client_ciphers_raw: List[int] = []
        self.client_extensions_raw: List[int] = []
        self.client_supported_versions_raw: List[int] = []
        self.client_alpn: Optional[str] = None
        self.server_cipher_raw: Optional[int] = None
        self.server_extensions_raw: List[int] = []
        self.server_negotiated_version_raw: Optional[int] = None
        self.server_alpn: Optional[str] = None
        self.session_id: bytes = b""
        self.tls13: bool = False
        self.supported_groups: List[int] = []
        self.key_share_group: Optional[int] = None
        self.sig_algs: List[int] = []

    def feed(self, buf: bytes) -> None:
        """Parse a buffer of TLS records."""
        off = 0
        n = len(buf)
        while off + 5 <= n:
            content_type = buf[off]
            legacy_version = (buf[off + 1] << 8) | buf[off + 2]
            length = (buf[off + 3] << 8) | buf[off + 4]
            if off + 5 + length > n:
                break
            body = buf[off + 5:off + 5 + length]
            self._handle_record(content_type, legacy_version, body)
            off += 5 + length

    def _handle_record(self, content_type: int, version: int, body: bytes) -> None:
        if content_type == HANDSHAKE:
            self._parse_handshakes(body)
        # change_cipher_spec / alert / app data handled implicitly

    def _parse_handshakes(self, data: bytes) -> None:
        off = 0
        n = len(data)
        while off + 4 <= n:
            htype = data[off]
            hlen = (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3]
            if off + 4 + hlen > n:
                break
            body = data[off + 4:off + 4 + hlen]
            try:
                if htype == CLIENT_HELLO:
                    self._parse_client_hello(body)
                elif htype == SERVER_HELLO:
                    self._parse_server_hello(body)
                elif htype == CERTIFICATE:
                    self._parse_certificate(body)
                elif htype == ENCRYPTED_EXTENSIONS:
                    self._parse_encrypted_extensions(body)
            except IndexError:
                # Truncated/malformed handshake; stop parsing this stream.
                break
            off += 4 + hlen

    def _parse_client_hello(self, body: bytes) -> None:
        off = 0
        # legacy_version
        version, off = _read_u16(body, off)
        self.client_hello = {"version": version}
        # random (32) - skip
        off += 32
        # session id
        sid_len = body[off]; off += 1
        off += sid_len
        # cipher suites
        cs_len, off = _read_u16(body, off)
        suites = []
        i = 0
        while i + 2 <= cs_len:
            c = (body[off + i] & 0xFF)
            c2 = body[off + i + 1] & 0xFF
            c_int = (c << 8) | c2
            self.client_ciphers_raw.append(c_int)
            hexname = f"0x{c:02X}{c2:02X}"
            suites.append(hexname)
            self.offered_ciphers.append(TLS_CONTENT_KEYS.get((c, c2), hexname))
            i += 2
        off += cs_len
        # compression methods
        comp_len = body[off]; off += 1
        off += comp_len
        # extensions
        self._parse_extensions(body, off, is_client=True)
        self.client_hello["cipher_suites"] = suites
        self._compute_ja3()
        self._compute_ja4()

    def _parse_server_hello(self, body: bytes) -> None:
        off = 0
        version, off = _read_u16(body, off)
        self.server_hello = {"version": version}
        self.server_negotiated_version_raw = version
        self.version = VERSION_NAMES.get(version, f"0x{version:04X}")
        from .models import TLS_VERSION_RANK
        self.version_rank = TLS_VERSION_RANK.get(self.version, 0)
        self.tls13 = self.version == "TLSv1.3"
        # random
        off += 32
        sid_len = body[off]; off += 1
        off += sid_len
        # cipher suite
        cs = (body[off] << 8) | body[off + 1]
        self.server_cipher_raw = cs
        off += 2
        self.cipher_hex = f"0x{cs:04X}"
        self.cipher_suite = TLS_CONTENT_KEYS.get(((cs >> 8) & 0xFF, cs & 0xFF), self.cipher_hex)
        comp = body[off]; off += 1
        # extensions
        self._parse_extensions(body, off, is_client=False)
        self._infer_key_exchange()
        self._compute_ja4s()

    def _parse_extensions(self, body: bytes, off: int, is_client: bool) -> None:
        if off + 2 > len(body):
            return
        total_len, off = _read_u16(body, off)
        end = off + total_len
        while off + 4 <= end:
            etype = (body[off] << 8) | body[off + 1]
            elen = (body[off + 2] << 8) | body[off + 3]
            edata = body[off + 4:off + 4 + elen]
            self._handle_extension(etype, edata, is_client)
            off += 4 + elen

    def _handle_extension(self, etype: int, edata: bytes, is_client: bool) -> None:
        names = {
            0x0000: "server_name",
            0x0001: "max_fragment_length",
            0x0005: "status_request",
            0x000a: "supported_groups",
            0x000b: "ec_point_formats",
            0x000d: "signature_algorithms",
            0x0010: "application_layer_protocol_negotiation",
            0x0013: "signed_certificate_timestamp",
            0x0017: "extended_master_secret",
            0x0018: "session_ticket",
            0x001b: "pre_shared_key",
            0x001c: "early_data",
            0x0023: "session_ticket",
            0x0029: "supported_versions",
            0x0033: "key_share",
            0x002d: "psk_key_exchange_modes",
        }
        name = names.get(etype, f"ext_{etype:04X}")
        self.extensions.append(name)
        if is_client:
            self.client_extensions_raw.append(etype)
        else:
            self.server_extensions_raw.append(etype)

        if etype == 0x0000 and is_client and len(edata) >= 5:
            # server_name list
            list_len = (edata[0] << 8) | edata[1]
            off = 2
            if off + 3 <= len(edata):
                ntype = edata[off]; off += 1
                nlen = (edata[off] << 8) | edata[off + 1]; off += 2
                self.sni = edata[off:off + nlen].decode("utf-8", "replace")
        elif etype == 0x0010 and len(edata) >= 3:
            # ALPN
            plen = edata[2]
            if len(edata) >= 3 + plen:
                val = edata[3:3 + plen].decode("utf-8", "replace")
                if is_client and not self.client_alpn:
                    self.client_alpn = val
                elif not is_client and not self.server_alpn:
                    self.server_alpn = val
        elif etype in (0x0029, 0x002b):
            # supported_versions
            if is_client:
                # ClientHello: [len(1)] then (ver 2 bytes) repeated
                if len(edata) >= 1:
                    nlen = edata[0]
                    off = 1
                    while off + 2 <= 1 + nlen:
                        ver = (edata[off] << 8) | edata[off + 1]
                        self.client_supported_versions_raw.append(ver)
                        vname = VERSION_NAMES.get(ver, f"0x{ver:04X}")
                        self.offered_versions.append(vname)
                        off += 2
            else:
                # ServerHello: single 2-byte version
                if len(edata) >= 2:
                    ver = (edata[0] << 8) | edata[1]
                    self.server_negotiated_version_raw = ver
                    if ver == 0x0304:
                        self.tls13 = True
                    from .models import TLS_VERSION_RANK
                    self.version = VERSION_NAMES.get(ver, self.version)
                    self.version_rank = TLS_VERSION_RANK.get(self.version, 0)
        elif etype == 0x000a and is_client:
            # supported_groups (client): first 2 bytes length
            if len(edata) >= 2:
                glen = (edata[0] << 8) | edata[1]
                off = 2
                while off + 2 <= 2 + glen:
                    g = (edata[off] << 8) | edata[off + 1]
                    self.supported_groups.append(g)
                    off += 2
        elif etype == 0x0033 and (is_client or self.tls13):
            # key_share: client sends (2B group, 2B len, data) pairs;
            # server sends single group
            off = 0
            if not is_client:
                # server: 2-byte group, 2-byte len
                if len(edata) >= 4:
                    g = (edata[0] << 8) | edata[1]
                    self.key_share_group = g
            else:
                # client: 2-byte total len then entries
                if len(edata) >= 2:
                    total_len = (edata[0] << 8) | edata[1]
                    off = 2
                    while off + 4 <= 2 + total_len:
                        g = (edata[off] << 8) | edata[off + 1]
                        self.key_share_group = self.key_share_group or g
                        off += 4
        elif etype == 0x000d and is_client:
            # signature_algorithms: 2B length then list of 2B algs
            if len(edata) >= 2:
                alen = (edata[0] << 8) | edata[1]
                off = 2
                while off + 2 <= 2 + alen:
                    a = (edata[off] << 8) | edata[off + 1]
                    self.sig_algs.append(a)
                    off += 2

    def _parse_encrypted_extensions(self, body: bytes) -> None:
        self.encrypted_extensions = {}
        off = 0
        if len(body) >= 2:
            total_len, off = _read_u16(body, off)
            end = off + total_len
            while off + 4 <= end:
                etype = (body[off] << 8) | body[off + 1]
                elen = (body[off + 2] << 8) | body[off + 3]
                edata = body[off + 4:off + 4 + elen]
                names = {
                    0x0029: "supported_versions",
                    0x002b: "key_share",
                    0x000d: "signature_algorithms",
                }
                self.encrypted_extensions[names.get(etype, f"ext_{etype:04X}")] = edata
                off += 4 + elen

    def _parse_certificate(self, body: bytes) -> None:
        if self.tls13:
            # TLS 1.3: context len + cert list; certs: 3-byte len + 3-byte len + DER
            if len(body) >= 4:
                ctx_len = body[0]; off = 1 + ctx_len
                # certificate_list is 3-byte length
                list_len = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]
                off += 3
                end = off + list_len
                while off + 3 <= end:
                    clen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]
                    off += 3
                    if off + clen <= end:
                        self.certificates.append(body[off:off + clen])
                        off += clen
        else:
            # TLS <=1.2: 3-byte length of cert_list
            if len(body) >= 3:
                list_len = (body[0] << 16) | (body[1] << 8) | body[2]
                off = 3
                end = off + list_len
                while off + 3 <= end:
                    clen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]
                    off += 3
                    if off + clen <= end:
                        self.certificates.append(body[off:off + clen])
                        off += clen

    def _infer_key_exchange(self) -> None:
        if not self.cipher_suite:
            return
        cs = self.cipher_suite
        group_code = self.key_share_group or (self.supported_groups[0] if self.supported_groups else None)
        group_name = NAMED_GROUPS.get(group_code) if group_code else None
        if self.tls13:
            # TLS 1.3 mandates (EC)DHE for all handshakes except PSK-only.
            if "PSK" in cs and "DHE" not in cs and "ECDHE" not in cs:
                self.key_exchange = "PSK"
            else:
                self.key_exchange = "ECDHE" if group_name else "DHE"
            self.key_exchange_group = group_name
            return
        # TLS <= 1.2
        if "ECDHE" in cs:
            self.key_exchange = "ECDHE"
            self.key_exchange_group = group_name
        elif "DHE" in cs:
            self.key_exchange = "DHE"
            self.key_exchange_group = group_name
        elif "ECDH" in cs and "DHE" not in cs:
            self.key_exchange = "ECDH (static)"
            self.key_exchange_group = group_name
        elif cs.startswith("TLS_RSA"):
            self.key_exchange = "RSA (static)"
        elif "PSK" in cs:
            self.key_exchange = "PSK"
        else:
            self.key_exchange = "unknown"

    @property
    def _detected_group(self) -> Optional[str]:
        return getattr(self, "_group", None)

    def _set_group(self, group: Optional[str]) -> None:
        self._group = group

    def _compute_ja3(self) -> None:
        """Compute a JA3 fingerprint from the ClientHello."""
        if not self.client_hello:
            return
        # JA3 = version,ciphers,extensions,groups,ec_point_formats
        version = self.client_hello.get("version", 0)
        ciphers = self.client_hello.get("cipher_suites", [])
        ext_types = []
        # We stored extension names only; reconstruct types from known mapping
        name_to_type = {
            "server_name": 0,
            "max_fragment_length": 1,
            "status_request": 5,
            "supported_groups": 10,
            "ec_point_formats": 11,
            "signature_algorithms": 13,
            "application_layer_protocol_negotiation": 16,
            "signed_certificate_timestamp": 18,
            "extended_master_secret": 23,
            "session_ticket": 35,
            "pre_shared_key": 41,
            "supported_versions": 43,
            "key_share": 51,
            "psk_key_exchange_modes": 45,
        }
        for e in self.extensions:
            if e in name_to_type:
                ext_types.append(name_to_type[e])
            elif e.startswith("ext_"):
                try:
                    ext_types.append(int(e[4:], 16))
                except ValueError:
                    pass
        groups_string = ""
        stringified = ",".join([str(version)] +
                               [c[2:] for c in ciphers] +
                               [str(e) for e in ext_types] +
                               ["0"])
        md5 = hashlib.md5(stringified.encode()).hexdigest()
        self.ja3 = md5

    def _compute_ja4(self) -> None:
        """Compute a JA4 client fingerprint from the ClientHello."""
        if not self.client_hello:
            return
        version = self.client_hello.get("version", 0)
        self.ja4 = compute_ja4(
            ciphers=self.client_ciphers_raw,
            extensions=self.client_extensions_raw,
            protocol_version=version,
            supported_versions=self.client_supported_versions_raw,
            sni=self.sni,
            alpn=self.client_alpn,
            sig_algs=self.sig_algs,
        )

    def _compute_ja4s(self) -> None:
        """Compute a JA4S server fingerprint from the ServerHello."""
        if not self.server_hello:
            return
        version = self.server_negotiated_version_raw or self.server_hello.get("version", 0)
        self.ja4s = compute_ja4s(
            cipher=self.server_cipher_raw or 0,
            extensions=self.server_extensions_raw,
            negotiated_version=version,
            alpn=self.server_alpn,
        )


def parse_tls_stream(server_ctx: bytes, client_ctx: bytes) -> TLSInfo:
    """Parse both directions of TLS traffic and return a TLSInfo summary.

    Args:
        server_ctx: server-to-client bytes beginning at the TLS handshake.
        client_ctx: client-to-server bytes beginning at the TLS handshake.
    """
    parser = TLSRecordParser()
    if server_ctx:
        parser.feed(server_ctx)
    if client_ctx:
        parser.feed(client_ctx)
    # Key-exchange inference depends on both the negotiated cipher (ServerHello)
    # and the key_share group (ClientHello), so recompute once both are known.
    parser._infer_key_exchange()
    info = TLSInfo()
    info.version = parser.version
    info.version_rank = parser.version_rank
    info.cipher_suite = parser.cipher_suite
    info.cipher_hex = parser.cipher_hex
    info.key_exchange = parser.key_exchange
    info.key_exchange_group = parser.key_exchange_group
    if parser.sig_algs:
        first = parser.sig_algs[0]
        info.signature_algorithm = SIG_ALGS.get(first, f"0x{first:04X}")
    info.server_name = parser.sni
    info.offered_ciphers = parser.offered_ciphers
    info.offered_versions = parser.offered_versions
    info.extensions = parser.extensions
    info.ja3 = parser.ja3
    info.ja4 = parser.ja4
    info.ja4s = parser.ja4s
    info.certificate = parser.certificates
    return info
