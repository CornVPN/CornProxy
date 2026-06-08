"""
antidpi.py — Full Anti-DPI Engine for CornProxy 0.3.0-beta
===========================================================

Techniques:
  TLS layer  — ClientHello parser, record splitting, SNI spoof, ext shuffle
  HTTP layer — GoodbyeDPI-style desync, chunked body, host tricks
  TCP layer  — TCP_NODELAY, SO_SNDBUF reduction, cork control
  Misc       — fake-prefix injection, composite auto-strategy
"""

from __future__ import annotations
import logging, os, platform, random, socket, struct, time
from typing import Dict, List, Optional, Tuple

log     = logging.getLogger("antidpi")
LINUX   = platform.system() == "Linux"

# ── Decoy SNI domains ────────────────────────────────────────────────────────
DECOY_SNIS: List[str] = [
    "www.bing.com", "ajax.googleapis.com",
    "cdn.cloudflare.com", "fonts.googleapis.com",
    "code.jquery.com",    "cdnjs.cloudflare.com",
    "www.microsoft.com",  "akamaized.net",
    "fastly.net",         "stackpath.bootstrapcdn.com",
]

# ── TLS constants ─────────────────────────────────────────────────────────────
TLS_HANDSHAKE    = 0x16
TLS_CLIENT_HELLO = 0x01
EXT_SNI          = 0x0000

# ── Mode registry ─────────────────────────────────────────────────────────────
ALL_MODES = [
    "off",
    "fragment",         "fragment_deep",    "fragment_random",
    "fragment_ssl",     "fragment_slow",
    "random_case",      "noise",            "double_host",
    "chunked_encoding", "http_obfuscation", "http_desync",
    "fake_request",
    "tls_fragment",     "tls_sni_spoof",    "tls_shuffle",
    "composite",
]

MODE_DESCRIPTIONS = {
    "off":              "No evasion",
    "fragment":         "2-packet TCP split (50 ms)",
    "fragment_deep":    "Byte-by-byte, 20 ms/byte — slow but thorough",
    "fragment_random":  "Random chunk sizes + random delays",
    "fragment_ssl":     "SSL-record chunks (50–100 B) with 20 ms gaps",
    "fragment_slow":    "5 chunks, 100–300 ms gaps",
    "random_case":      "HTTP header name case randomisation",
    "noise":            "Fake X-* headers + spoofed source IPs",
    "double_host":      "Double-colon Host mangling (Host::)",
    "chunked_encoding": "HTTP body → chunked transfer-encoding",
    "http_obfuscation": "random_case + noise + desync combined",
    "http_desync":      "GoodbyeDPI double-space + trailing-dot Host",
    "fake_request":     "Fake HTTP GET prefix before real request",
    "tls_fragment":     "Split ClientHello into 2 TLS records at SNI",
    "tls_sni_spoof":    "Replace SNI with CDN decoy domain",
    "tls_shuffle":      "Shuffle TLS extensions (defeats JA3 fingerprint)",
    "composite":        "TLS-split + SNI spoof + HTTP desync (recommended)",
}


# ─────────────────────────────────────────────────────────────────────────────
#  TLS ClientHello parser / builder
# ─────────────────────────────────────────────────────────────────────────────

class TLSExtension:
    __slots__ = ("type", "data")

    def __init__(self, ext_type: int, data: bytes):
        self.type = ext_type
        self.data = data

    @property
    def raw(self) -> bytes:
        return struct.pack(">HH", self.type, len(self.data)) + self.data

    @classmethod
    def from_bytes(cls, buf: bytes, offset: int) -> Tuple["TLSExtension", int]:
        if offset + 4 > len(buf):
            raise ValueError("truncated extension")
        t   = struct.unpack_from(">H", buf, offset)[0]
        ln  = struct.unpack_from(">H", buf, offset + 2)[0]
        dat = buf[offset + 4 : offset + 4 + ln]
        return cls(t, dat), offset + 4 + ln


class ClientHello:
    """Parse + re-build TLS ClientHello; supports SNI replacement,
    extension shuffling, and record splitting."""

    def __init__(self):
        self.version:       int               = 0x0303
        self.random:        bytes             = b"\x00" * 32
        self.session_id:    bytes             = b""
        self.cipher_suites: bytes             = b""
        self.compression:   bytes             = b"\x00"
        self.extensions:    List[TLSExtension] = []
        self._rec_version:  int               = 0x0301
        self._valid:        bool              = False

    # ── parse ─────────────────────────────────────────────────────────────────

    @classmethod
    def parse(cls, data: bytes) -> Optional["ClientHello"]:
        if len(data) < 9 or data[0] != TLS_HANDSHAKE:
            return None
        obj = cls()
        obj._rec_version = struct.unpack_from(">H", data, 1)[0]
        hs = data[5:]
        if not hs or hs[0] != TLS_CLIENT_HELLO:
            return None

        pos = 4                         # skip hs-type(1) + hs-len(3)
        if pos + 2 > len(hs): return None
        obj.version = struct.unpack_from(">H", hs, pos)[0]; pos += 2
        if pos + 32 > len(hs): return None
        obj.random  = hs[pos : pos + 32];                   pos += 32
        sid = hs[pos]; pos += 1
        obj.session_id  = hs[pos : pos + sid]; pos += sid
        cs = struct.unpack_from(">H", hs, pos)[0]; pos += 2
        obj.cipher_suites = hs[pos : pos + cs]; pos += cs
        cm = hs[pos]; pos += 1
        obj.compression = hs[pos : pos + cm]; pos += cm

        if pos + 2 <= len(hs):
            ext_total = struct.unpack_from(">H", hs, pos)[0]; pos += 2
            ext_end   = pos + ext_total
            while pos < ext_end:
                try:
                    ext, pos = TLSExtension.from_bytes(hs, pos)
                    obj.extensions.append(ext)
                except ValueError:
                    break

        obj._valid = True
        return obj

    # ── serialise ─────────────────────────────────────────────────────────────

    def _hello_body(self) -> bytes:
        ext_bytes = b"".join(e.raw for e in self.extensions)
        return (
            struct.pack(">H", self.version)
            + self.random
            + bytes([len(self.session_id)]) + self.session_id
            + struct.pack(">H", len(self.cipher_suites)) + self.cipher_suites
            + bytes([len(self.compression)]) + self.compression
            + struct.pack(">H", len(ext_bytes)) + ext_bytes
        )

    def to_record(self) -> bytes:
        body = self._hello_body()
        hs   = bytes([TLS_CLIENT_HELLO]) + struct.pack(">I", len(body))[1:] + body
        return struct.pack(">BHH", TLS_HANDSHAKE, self._rec_version, len(hs)) + hs

    # ── SNI ──────────────────────────────────────────────────────────────────

    def get_sni(self) -> Optional[str]:
        for e in self.extensions:
            if e.type == EXT_SNI and len(e.data) >= 5:
                n = struct.unpack_from(">H", e.data, 3)[0]
                return e.data[5 : 5 + n].decode("ascii", errors="ignore")
        return None

    def set_sni(self, sni: str) -> None:
        b = sni.encode("ascii")
        sni_data = (struct.pack(">H", len(b) + 3)
                    + b"\x00"
                    + struct.pack(">H", len(b))
                    + b)
        for i, e in enumerate(self.extensions):
            if e.type == EXT_SNI:
                self.extensions[i] = TLSExtension(EXT_SNI, sni_data)
                return
        self.extensions.insert(0, TLSExtension(EXT_SNI, sni_data))

    # ── extension ops ─────────────────────────────────────────────────────────

    def shuffle_extensions(self, *, keep_sni_first: bool = True) -> None:
        sni   = [e for e in self.extensions if e.type == EXT_SNI]
        other = [e for e in self.extensions if e.type != EXT_SNI]
        random.shuffle(other)
        self.extensions = (sni + other) if keep_sni_first else other + sni

    # ── record splitting ──────────────────────────────────────────────────────

    def split_at_sni(self) -> Tuple[bytes, bytes]:
        """
        Split the ClientHello record into two TLS records exactly at
        the start of the SNI extension — the most effective split point.
        """
        full    = self.to_record()
        payload = full[5:]
        ver     = self._rec_version

        # Walk _hello_body() (no hs-header prefix) to find SNI offset
        body = self._hello_body()
        pos  = 0
        pos += 2 + 32                                         # version(2) + random(32)
        if pos >= len(body): return full, b""
        sid = body[pos]; pos += 1 + sid                       # session id
        if pos + 2 > len(body): return full, b""
        cs  = struct.unpack_from(">H", body, pos)[0]; pos += 2 + cs  # cipher suites
        if pos >= len(body): return full, b""
        cm  = body[pos]; pos += 1 + cm                        # compression
        if pos + 2 > len(body): return full, b""
        pos += 2                                               # ext total length

        split_in_body = pos   # default: split at first extension
        while pos + 4 <= len(body):
            t  = struct.unpack_from(">H", body, pos)[0]
            ln = struct.unpack_from(">H", body, pos + 2)[0]
            if t == EXT_SNI:
                split_in_body = pos
                break
            pos += 4 + ln

        # In the serialised payload: hs-header(4) is prepended, then body
        split_in_payload = 4 + split_in_body
        if split_in_payload <= 0 or split_in_payload >= len(payload):
            split_in_payload = max(1, len(payload) // 2)

        p1 = payload[:split_in_payload]
        p2 = payload[split_in_payload:]
        if not p2: return full, b""
        r1 = struct.pack(">BHH", TLS_HANDSHAKE, ver, len(p1)) + p1
        r2 = struct.pack(">BHH", TLS_HANDSHAKE, ver, len(p2)) + p2
        return r1, r2


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP layer helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_http(data: bytes) -> bool:
    return data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ",
                        b"PATC", b"DELE", b"OPTI", b"CONN")


def obfuscate_http_headers(data: bytes, mode: str) -> bytes:
    """Called by cornproxy for header-level transforms (no socket needed)."""
    if not _is_http(data):
        return data
    if mode in ("random_case", "http_obfuscation"):
        data = _hdr_random_case(data)
    if mode in ("noise", "http_obfuscation"):
        data = _hdr_noise(data)
    if mode == "double_host":
        data = _hdr_double_host(data)
    if mode == "chunked_encoding":
        data = _hdr_chunked(data)
    if mode in ("http_desync", "http_obfuscation"):
        data = _http_desync(data)
    return data


def _hdr_random_case(data: bytes) -> bytes:
    lines  = data.split(b"\r\n")
    result = []
    for i, line in enumerate(lines):
        if i == 0 or b":" not in line:
            result.append(line)
            continue
        name, _, val = line.partition(b":")
        try:
            ns = name.decode("ascii")
            nr = "".join(c.upper() if j % 2 == 0 else c.lower() for j, c in enumerate(ns))
            result.append(nr.encode() + b":" + val)
        except Exception:
            result.append(line)
    return b"\r\n".join(result)


def _hdr_noise(data: bytes) -> bytes:
    ip  = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    hdr = (f"X-Fwd-{random.randint(100,999)}: {random.randint(0,9999999)}\r\n"
           f"X-Real-IP: {ip}\r\n").encode()
    return data.replace(b"\r\n\r\n", b"\r\n" + hdr + b"\r\n", 1)


def _hdr_double_host(data: bytes) -> bytes:
    lines = data.split(b"\r\n")
    return b"\r\n".join(
        line.replace(b"Host:", b"Host::", 1)
        if line.lower().startswith(b"host:") else line
        for line in lines
    )


def _hdr_chunked(data: bytes) -> bytes:
    if b"\r\n\r\n" not in data:
        return data
    head, body = data.split(b"\r\n\r\n", 1)
    if not body:
        return data
    lines = [l for l in head.split(b"\r\n")
             if not l.lower().startswith(b"content-length:")]
    lines.append(b"Transfer-Encoding: chunked")
    new_head = b"\r\n".join(lines)
    sz  = random.randint(16, 64)
    enc = b"".join(f"{len(body[i:i+sz]):x}".encode() + b"\r\n"
                   + body[i:i+sz] + b"\r\n"
                   for i in range(0, len(body), sz)) + b"0\r\n\r\n"
    return new_head + b"\r\n\r\n" + enc


def _http_desync(data: bytes) -> bytes:
    """
    GoodbyeDPI-style tricks:
      • double space after method  →  misidentifies request structure
      • trailing dot on Host       →  Host: example.com.
      • random noise padding header
    """
    try:
        sep   = data.find(b"\r\n\r\n")
        head  = data[:sep] if sep != -1 else data
        tail  = data[sep:] if sep != -1 else b""
        lines = head.split(b"\r\n")
        out   = []
        for i, line in enumerate(lines):
            if i == 0:
                m, _, rest = line.partition(b" ")
                out.append(m + b"  " + rest)        # double space
            elif line.lower().startswith(b"host:"):
                out.append(line.rstrip() + b".")    # trailing dot
            else:
                out.append(line)
        out.append(f"X-Pad-{random.randint(10,99)}: {os.urandom(3).hex()}".encode())
        return b"\r\n".join(out) + tail
    except Exception:
        return data


def _fake_http_prefix(host: str) -> bytes:
    return (
        f"GET /{os.urandom(4).hex()}.js HTTP/1.1\r\n"
        f"Host: {host}\r\nConnection: keep-alive\r\n\r\n"
    ).encode()


# ─────────────────────────────────────────────────────────────────────────────
#  Socket helpers
# ─────────────────────────────────────────────────────────────────────────────

def _nodelay(sock: socket.socket) -> None:
    try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception: pass


def _cork(sock: socket.socket, enable: bool) -> None:
    if not LINUX: return
    try: sock.setsockopt(socket.IPPROTO_TCP, 3, 1 if enable else 0)   # TCP_CORK = 3
    except Exception: pass


def _small_buf(sock: socket.socket, size: int = 4096) -> Optional[int]:
    try:
        old = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, size)
        return old
    except Exception:
        return None


def _restore_buf(sock: socket.socket, old: Optional[int]) -> None:
    if old is None: return
    try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, old)
    except Exception: pass


# ─────────────────────────────────────────────────────────────────────────────
#  Main engine
# ─────────────────────────────────────────────────────────────────────────────

class AntiDPI:
    """
    Central anti-DPI engine.

        engine = AntiDPI("composite")
        engine.apply(sock, raw_bytes, "example.com")
        transformed = engine.transform_http(request_bytes)
    """

    def __init__(self, mode: str = "composite"):
        self.mode = mode if mode in ALL_MODES else "composite"
        self._host_ok:   Dict[str, str] = {}
        self._host_fail: Dict[str, int] = {}

    # ── public ────────────────────────────────────────────────────────────────

    def apply(self, sock: socket.socket, data: bytes, host: str = "") -> None:
        if self.mode == "off" or not data:
            sock.sendall(data)
            return
        try:
            self._dispatch(sock, data, host)
        except Exception as exc:
            log.debug("AntiDPI %s failed for %s: %s — raw send", self.mode, host, exc)
            try: sock.sendall(data)
            except Exception: pass

    def transform_http(self, data: bytes) -> bytes:
        if self.mode == "off": return data
        return obfuscate_http_headers(data, self.mode)

    def next_mode(self) -> str:
        idx = ALL_MODES.index(self.mode) if self.mode in ALL_MODES else 0
        self.mode = ALL_MODES[(idx + 1) % len(ALL_MODES)]
        return self.mode

    def describe(self) -> str:
        return MODE_DESCRIPTIONS.get(self.mode, "Unknown")

    # ── dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, sock: socket.socket, data: bytes, host: str) -> None:
        m = self.mode

        # ── TCP fragmentation group ──
        if m == "fragment":
            _nodelay(sock)
            sock.sendall(data[:1]); time.sleep(0.05); sock.sendall(data[1:])

        elif m == "fragment_deep":
            _nodelay(sock)
            for b in data: sock.sendall(bytes([b])); time.sleep(0.02)

        elif m == "fragment_random":
            _nodelay(sock)
            pos = 0
            while pos < len(data):
                sz = random.randint(1, max(2, (len(data) - pos) // 2))
                sock.sendall(data[pos : pos + sz]); pos += sz
                time.sleep(random.uniform(0.01, 0.05))

        elif m == "fragment_ssl":
            _nodelay(sock)
            pos = 0
            while pos < len(data):
                sz = random.randint(50, 100)
                sock.sendall(data[pos : pos + sz]); pos += sz
                time.sleep(0.02)

        elif m == "fragment_slow":
            _nodelay(sock)
            sz = max(1, len(data) // 5)
            for i in range(0, len(data), sz):
                sock.sendall(data[i : i + sz])
                time.sleep(random.uniform(0.1, 0.3))

        # ── HTTP group ──
        elif m in ("random_case", "noise", "double_host",
                   "chunked_encoding", "http_obfuscation", "http_desync"):
            sock.sendall(obfuscate_http_headers(data, m))

        elif m == "fake_request":
            _nodelay(sock)
            sock.sendall(_fake_http_prefix(host or "www.google.com"))
            time.sleep(0.07)
            sock.sendall(data)

        # ── TLS group ──
        elif m == "tls_fragment":
            ch = ClientHello.parse(data)
            if ch:
                r1, r2 = ch.split_at_sni()
                log.debug("tls_fragment: %dB + %dB → %s", len(r1), len(r2), host)
                _nodelay(sock)
                sock.sendall(r1); time.sleep(0.02); sock.sendall(r2)
            else:
                sock.sendall(data)

        elif m == "tls_sni_spoof":
            ch = ClientHello.parse(data)
            if ch:
                real = ch.get_sni()
                decoy = random.choice(DECOY_SNIS)
                ch.set_sni(decoy)
                log.debug("tls_sni_spoof: %s → %s", real, decoy)
                sock.sendall(ch.to_record())
            else:
                sock.sendall(data)

        elif m == "tls_shuffle":
            ch = ClientHello.parse(data)
            if ch:
                ch.shuffle_extensions()
                sock.sendall(ch.to_record())
            else:
                sock.sendall(data)

        # ── Composite ──
        elif m == "composite":
            self._composite(sock, data, host)

        else:
            sock.sendall(data)

    # ── composite strategy ───────────────────────────────────────────────────

    def _composite(self, sock: socket.socket, data: bytes, host: str) -> None:
        """
        Smart composite:
          TLS  → shuffle extensions + spoof SNI + split at SNI boundary
          HTTP → desync (double-space + trailing dot) + noise header
          else → random fragmentation
        """
        if len(data) > 5 and data[0] == TLS_HANDSHAKE:
            ch = ClientHello.parse(data)
            if ch:
                ch.shuffle_extensions()
                real_sni = ch.get_sni()
                decoy    = random.choice(DECOY_SNIS)
                ch.set_sni(decoy)
                log.debug("composite TLS: shuffle + SNI %s→%s + split → %s",
                          real_sni, decoy, host)
                r1, r2 = ch.split_at_sni()
                _nodelay(sock)
                sock.sendall(r1); time.sleep(0.02); sock.sendall(r2)
                return

        if _is_http(data):
            modified = _http_desync(data)
            modified = _hdr_noise(modified)
            _nodelay(sock)
            sock.sendall(modified)
            return

        # Generic traffic — random fragmentation with small buffer
        _nodelay(sock)
        old = _small_buf(sock, 8192)
        pos = 0
        while pos < len(data):
            sz = random.randint(32, 512)
            sock.sendall(data[pos : pos + sz])
            pos += sz
            time.sleep(0.01)
        _restore_buf(sock, old)


# ─────────────────────────────────────────────────────────────────────────────
#  Self-test
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level convenience API  (called by cornproxy.py)
# ─────────────────────────────────────────────────────────────────────────────

# Singleton engine — cornproxy.py updates _engine.mode via set_mode()
_engine = AntiDPI("composite")


def set_mode(mode: str) -> None:
    """Update the singleton engine mode."""
    _engine.mode = mode if mode in ALL_MODES else "off"


def get_mode() -> str:
    return _engine.mode


def next_mode() -> str:
    return _engine.next_mode()


def describe_mode() -> str:
    return _engine.describe()


def antidpi_send(sock: socket.socket, data: bytes, mode: str,
                 host: str = "") -> None:
    """Send data with the given DPI evasion mode (module-level helper)."""
    prev = _engine.mode
    _engine.mode = mode if mode in ALL_MODES else "off"
    _engine.apply(sock, data, host)
    _engine.mode = prev


def build_connect_request(target_host: str, target_port: int,
                           proxy_host: str,
                           user: Optional[str], pwd: Optional[str],
                           mode: str) -> bytes:
    """
    Build an HTTP CONNECT request with DPI-evasion headers applied.
    Returns the raw bytes to send to the upstream proxy.
    """
    import base64 as _b64
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
    if user and pwd:
        token = _b64.b64encode(f"{user}:{pwd}".encode()).decode()
        req  += f"Proxy-Authorization: Basic {token}\r\n"
    if mode in ("noise", "http_obfuscation", "composite"):
        ip = (f"{random.randint(1,254)}.{random.randint(0,255)}"
              f".{random.randint(0,255)}.{random.randint(1,254)}")
        req += f"X-Forwarded-For: {ip}\r\n"
        req += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    req += "\r\n"
    return req.encode()


def forward_with_antidpi(src: socket.socket, dst: socket.socket,
                          direction: str, host: str,
                          mode: str,
                          stats_callback=None) -> None:
    """
    Relay traffic between src and dst.
    Anti-DPI is applied only to the FIRST outbound chunk (ClientHello /
    first HTTP request); subsequent chunks relay at full speed.
    """
    first = True
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            if first and direction == "sent" and mode != "off":
                _engine.mode = mode if mode in ALL_MODES else "off"
                _engine.apply(dst, data, host)
            else:
                dst.sendall(data)
            first = False
            if stats_callback:
                stats_callback(direction, len(data), host)
    except Exception as exc:
        log.debug("forward_with_antidpi %s %s: %s", direction, host, exc)
    finally:
        for s in (src, dst):
            try: s.close()
            except Exception: pass

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")
    print("=== antidpi.py self-test ===\n")

    # Build a minimal but real ClientHello
    sni_val  = b"example.com"
    sni_data = struct.pack(">H", len(sni_val) + 3) + b"\x00" + struct.pack(">H", len(sni_val)) + sni_val
    sni_ext  = struct.pack(">HH", 0x0000, len(sni_data)) + sni_data
    ext_bytes = sni_ext

    hello_body = (
        b"\x03\x03"          # version TLS 1.2
        + b"\xAB" * 32       # random
        + b"\x00"            # session id len
        + b"\x00\x02\x00\x2f"  # 1 cipher suite
        + b"\x01\x00"        # compression: null
        + struct.pack(">H", len(ext_bytes)) + ext_bytes
    )
    hs = bytes([0x01]) + struct.pack(">I", len(hello_body))[1:] + hello_body
    raw = struct.pack(">BHH", 0x16, 0x0301, len(hs)) + hs

    ch = ClientHello.parse(raw)
    assert ch is not None,        "parse failed"
    assert ch.get_sni() == "example.com", f"bad SNI: {ch.get_sni()}"
    print(f"[OK] SNI parsed:    {ch.get_sni()}")

    ch.set_sni("www.bing.com")
    assert ch.get_sni() == "www.bing.com"
    print(f"[OK] SNI replaced:  {ch.get_sni()}")

    before = len(ch.extensions)
    ch.shuffle_extensions()
    assert len(ch.extensions) == before
    print(f"[OK] Extensions shuffled ({before} total)")

    r1, r2 = ch.split_at_sni()
    assert r1 and r2
    print(f"[OK] Record split:  {len(r1)}B  +  {len(r2)}B")

    rec = ch.to_record()
    ch2 = ClientHello.parse(rec)
    assert ch2 is not None and ch2.get_sni() == "www.bing.com"
    print(f"[OK] Round-trip:    rebuilt {len(rec)}B, SNI preserved")

    # HTTP desync
    req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    out = _http_desync(req)
    first_line = out.split(b"\r\n")[0]
    assert b"  " in first_line, "double space missing"
    print(f"[OK] HTTP desync first line: {first_line.decode()!r}")

    host_line = [l for l in out.split(b"\r\n") if l.lower().startswith(b"host:")][0]
    assert host_line.endswith(b"."), "trailing dot missing"
    print(f"[OK] Host trailing dot: {host_line.decode()!r}")

    # Chunked
    post = b"POST /api HTTP/1.1\r\nHost: x.com\r\nContent-Length: 11\r\n\r\nHello World"
    enc  = _hdr_chunked(post)
    assert b"chunked" in enc.lower()
    assert b"Content-Length" not in enc
    print(f"[OK] Chunked encoding applied ({len(enc)}B)")

    print(f"\n[OK] All modes ({len(ALL_MODES)}):")
    for m in ALL_MODES:
        print(f"     {m:<22}  {MODE_DESCRIPTIONS[m]}")

    print("\n✓  antidpi.py all tests passed")
