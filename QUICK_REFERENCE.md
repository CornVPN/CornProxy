# 🌽 CornProxy v0.3.0-beta — Quick Reference

## Installation

```bash
pip install rich pyfiglet colorama PySocks plotext
# Optional but recommended:
pip install pycryptodome
```

## Quick Start

```bash
python3 cornproxy.py
```

Choose mode:
1. **Manual proxy** — single upstream
2. **Proxy pool** — auto-rotating (fetches free proxies)
3. **Direct** — no upstream (logging only)
4. **MITM** — decrypt HTTPS (experimental)
5. **Bridge** — Tor-style relays (recommended for heavy filtering)
6. **MTProto** — Telegram native (tap the tg:// link on phone)

---

## Using with Applications

### Telegram via SOCKS5
```
Telegram Settings → Data & Storage → Proxy Settings
Type: SOCKS5
Host: server-ip
Port: 8888
```

### Telegram via MTProto (better)
```
Select mode 6 (MTProto) on startup
Copy the tg://proxy?... link
Open on phone → auto-configures
```

### Firefox/Chrome
```
Settings → Network → Proxy
Proxy type: SOCKS5
Address: server-ip:8888
```

### curl
```bash
curl -x socks5://server-ip:8888 https://example.com
```

### All apps (HTTP CONNECT)
```bash
# Most apps support this natively
# Settings → Proxy → HTTP Proxy
# Host: server-ip, Port: 8888
```

---

## DPI Modes (Press 'd' to cycle)

| Mode | Speed | Works Best For |
|------|-------|---|
| `off` | Fast | Testing, light ISP |
| `fragment` | Fast | Light blocking |
| `fragment_random` | Medium | Russia, Belarus |
| `fragment_ssl` | Medium | TLS-targeted DPI |
| `fragment_slow` | Slow | UAE, heavy filtering |
| `chunked_encoding` | Fast | Egypt (Forcepoint) |
| `http_desync` | Fast | Header-based DPI |
| `tls_sni_spoof` | Fast | SNI-based blocking |
| `composite` | Medium | Most situations |

**Recommended by region:**
- 🇷🇺 Russia: `fragment_random` + bridge
- 🇧🇾 Belarus: `fragment_ssl` + bridge
- 🇪🇬 Egypt: `chunked_encoding` + bridge
- 🇦🇪 UAE: `fragment_slow` + bridge
- 🇸🇦 Saudi: `fragment_random` + bridge
- 🇲🇦 Morocco: `fragment` (optional bridge)

---

## Bridge Mode Setup

1. Create `cornproxy_bridges.txt`:
```
# One bridge per line
bridge1.example.com:9999
bridge2.example.com:8080
```

2. Get bridges from:
   - https://bridges.torproject.org (rotate daily)
   - GitHub: search "proxy bridges"
   - Run your own: `python3 bridge_server.py 9999 real-proxy.com 8080`

3. Start CornProxy mode 5 (Bridge)

---

## Hot keys

| Key | Action |
|-----|--------|
| `d` | Cycle DPI mode |
| `r` | Reset stats |
| `s` | Save log |
| `p` | Update proxy pool |
| `q` | Quit |

---

## Config File (auto-created)

**cornproxy.conf:**
```ini
[cornproxy]
listen_port = 8888
dpi_mode = fragment_random

[mtproto]
enabled = true
port = 8443
secret = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
```

Edit manually or let the interactive setup regenerate it.

---

## TUI (Text User Interface)

```
┌─────────────────────────────────────────┐
│ CornProxy 0.3.0-beta "Sweety kitty"      │
├─────────────────────────────────────────┤
│ Active connections: 12                  │
│ Uploaded: 45.2 MB                       │
│ Downloaded: 234.1 MB                    │
│ DPI mode: composite                     │
│ Available bridges: 7                    │
├─────────────────────────────────────────┤
│ [Bandwidth graph]                       │
│                                         │
│ Top hosts:                              │
│   google.com      34.5 MB  ▓▓▓▓▓▓▓▓   │
│   github.com      12.3 MB  ▓▓▓         │
│   wikipedia.org   8.7 MB   ▓▓          │
└─────────────────────────────────────────┘

Hotkeys: [r] Reset  [s] Save log  [p] Update pool  [d] DPI mode  [q] Quit
```

---

## Troubleshooting

### Connection hangs
→ Try different DPI mode (press `d`)
→ Update bridge pool (press `p`)

### Very slow
→ `fragment_slow` or `fragment_deep` are intentionally slow
→ Try `fragment_random` instead
→ Check bridge quality (high latency bridges hurt)

### Bridge connection refused
→ Bridge may be offline (automatically removed after failure)
→ Add more bridges to `cornproxy_bridges.txt`
→ Try different bridge

### HTTPS certificate warnings
→ Use MITM mode (mode 4) and install CA certificate
→ Or accept cert warnings (depends on client)

### DPI bypass not working
→ Try `bridge` mode (combines bridge + DPI)
→ Try slower modes: `fragment_slow` > `fragment_deep`
→ Layer with VPN: VPN → CornProxy → site

---

## Performance Tips

1. **Choose right DPI mode:**
   - Light filtering → `fragment`
   - Heavy filtering → `fragment_slow` or bridge mode
   - Egypt specifically → `chunked_encoding`

2. **Use multiple bridges:**
   - Rotation helps avoid blocking
   - Load balancing improves speed
   - Different IPs for different servers

3. **Combine with other tools:**
   - VPN → CornProxy → Tor → site (slow but very hidden)
   - CornProxy → Tor → site (fast)
   - CornProxy → VPN → site (ok)

4. **Monitor bandwidth:**
   - Save logs (press `s`)
   - Check which hosts slow you down
   - Use direct mode (mode 3) for testing

---

## Security Notes

- Bridge IPs should be private/fresh (not public blocklists)
- Rotate bridges regularly (get new ones from Tor project weekly)
- Combine with VPN for extra privacy
- Don't share bridge IPs publicly
- Keep logs minimal (sensitive data)

---

## Support & Contributing

- Report bugs: save log (press `s`), include details
- Request features: consider regional needs
- Share working bridges: private channels only
- Test new modes: feedback helps improvement

---

## Version & License

- **Version:** 0.2.0-beta (Early Beta → Beta)
- **Codename:** Steppe Fox
- **License:** MIT (free, open source)

---

## Glossary

- **DPI** = Deep Packet Inspection (network censorship)
- **Bridge** = Intermediate relay (like Tor bridges)
- **MTProto** = Telegram's native protocol
- **SOCKS5** = Standard proxy protocol
- **SNI** = Server Name Indication in TLS
- **Anti-DPI** = Techniques to evade Deep Packet Inspection

---

Last updated: 2026-06-08
