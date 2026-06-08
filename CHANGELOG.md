# CornProxy Changelog

---

## [0.3.0-beta] "Sweety kitty" — 2026-06-08

### 🎉 Early Beta → Beta

### Added
- **MTProto proxy mode** (mode 6) — Telegram's native proxy protocol
  - Obfuscated handshake with AES-CTR key derivation
  - DC routing: auto-detects DC1-DC5 from client init
  - dd-secret support (fake-TLS mode, looks like HTTPS)
  - Generates `tg://proxy?...` link on startup
  - Separate configurable port (default 8443)
- **Config file** (`cornproxy.conf`) — settings persist between runs
  - Auto-save after mode selection
  - Auto-load on startup
- **SOCKS4/SOCKS5 inbound** — CornProxy now accepts SOCKS connections, not only HTTP
  - `socks5://host:port` works natively
  - SOCKS4a (domain resolution) supported
  - Auto-detection via first-byte peek (`0x04` / `0x05`)
- **Bridge mode** (mode 5) — intermediate relay nodes like Tor bridges
  - Bridge pool with liveness testing
  - Random bridge selection per connection
  - Auto-removal of dead bridges
  - `cornproxy_bridges.txt` for bridge list
- **Anti-DPI expansion** — 13 modes total
  - `fragment_random` — random chunk sizes + random delays
  - `fragment_ssl` — SSL-record aware fragmentation (50–100 B)
  - `fragment_slow` — very slow delivery (100–300 ms gaps)
  - `chunked_encoding` — HTTP body → chunked transfer-encoding
  - `http_obfuscation` — mixed case + noise headers
  - `tls_shuffle` — randomize TLS ClientHello extensions
  - `tls_spoof` — spoof TLS version bytes
- **Telegram DC awareness** — knows DC1–DC5 IPs, falls back gracefully
- **Bind fix** — `start_regular_server` now binds `0.0.0.0` (was `127.0.0.1`)
- **DPI mode prompt** at startup (no longer only via hotkey)
- **Regional config guide** (`REGIONAL_CONFIG.md`) for RU/BY/EG/AE/SA/MA

### Changed
- Version string moved to `__version__` / `__codename__` / `__build_date__`
- Main menu expanded to 6 modes
- TUI now shows bridge count OR proxy count depending on active mode
- MTProto server starts alongside regular proxy (both ports active)
- `create_tunnel_with_retry` routes through bridge if `bridge_mode` is set

### Fixed
- `handle_client` no longer hangs on SOCKS connections (first-byte peek)
- `dpi_mode` cycle now includes all 13 modes
- `start_regular_server` bind address corrected to `0.0.0.0`

---

## [0.1.0-alpha] "Kernel Panic" — 2026-04-20

### Initial release (early alpha → early beta)

- HTTP proxy engine with CONNECT support
- Upstream proxy pool (HTTP, SOCKS4, SOCKS5)
- Anti-DPI: `fragment`, `fragment_deep`, `random_case`, `noise`,
  `double_host`, `fake_request`
- MITM mode with dynamic certificate generation
- Rich TUI with live stats, bandwidth graph
- Proxy pool auto-fetch from public sources
- Background pool health checker
- Regional DPI advice (RU, BY, EG, TR, AE, SA, MA)
- Logging to file

---

## Roadmap

### [0.5.0-beta] 
- [ ] Automatic Tor bridge fetching via bridges.torproject.org API
- [ ] Multi-hop bridge chaining (2+ hops)
- [ ] HTTP/2 support
- [ ] DNS-over-HTTPS resolver
- [ ] Web UI (optional, localhost only)
- [ ] Windows installer / Linux systemd unit

### [0.5.0-beta] planned
- [ ] Shadowsocks upstream support
- [ ] WireGuard tunnel integration
- [ ] Crowdsourced bridge reporting
- [ ] Auto DPI mode selection based on detected region

### [1.0.0] planned
- [ ] Stable API
- [ ] Full test suite
- [ ] Packaged release (pip / deb / exe)
