<div align="center">🌽 CornProxy

High-performance local HTTP/SOCKS proxy engine with traffic monitoring and proxy pooling

<p>"Python" (https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
"License" (https://img.shields.io/github/license/CornVPN/CornProxy?style=for-the-badge)
"Stars" (https://img.shields.io/github/stars/CornVPN/CornProxy?style=for-the-badge)
"Issues" (https://img.shields.io/github/issues/CornVPN/CornProxy?style=for-the-badge)
"Status" (https://img.shields.io/badge/status-experimental-orange?style=for-the-badge)

</p>Lightweight local proxy engine for HTTP and SOCKS traffic with proxy pools, traffic observability and experimental DPI evasion techniques.

</div>---

✨ Features

- 🌐 HTTP proxy support
- 🔒 HTTPS CONNECT tunneling
- 🔄 Proxy pool with automatic rotation
- ⚡ SOCKS4 / SOCKS5 support
- 📊 Real-time traffic monitoring
- 📈 Terminal dashboard (Rich + Plotext)
- 📝 CSV logging
- 🔍 Per-host statistics
- 🧪 Experimental DPI evasion modes
- 🎓 Educational and research oriented

---

🏗 Architecture

          Client Applications
                  │
                  ▼
          ┌────────────────┐
          │    CornProxy   │
          │ Local Engine   │
          └────────────────┘
                  │
                  ▼
          ┌────────────────┐
          │   Proxy Pool   │
          │ HTTP / SOCKS   │
          └────────────────┘
                  │
                  ▼
             Target Server

---

🚀 Quick Start

Clone the repository:

git clone https://github.com/CornVPN/CornProxy.git
cd CornProxy

Install dependencies:

pip install -r requirements.txt

Run:

python cornproxy.py

---

⚙ Modes

Direct Mode

Client → CornProxy → Target

Manual Proxy Mode

Client → CornProxy → Proxy → Target

Proxy Pool Mode

Client → CornProxy → Proxy Pool → Target

---

📊 Dashboard

CornProxy provides:

- Upload / Download statistics
- Active connections
- Per-host traffic analysis
- Live speed graph
- Proxy pool status

---

🧪 DPI Modes

Mode| Description
"off"| Disabled
"fragment"| Basic packet fragmentation
"random_case"| Header case randomization
"noise"| Extra header injection

«DPI features are experimental.»

---

🗺 Roadmap

- [x] HTTP proxy support
- [x] SOCKS4 / SOCKS5 support
- [x] Proxy pool
- [x] Traffic statistics
- [x] TUI dashboard
- [ ] IPv6 support
- [ ] YAML configuration
- [ ] Async architecture
- [ ] Docker support
- [ ] PAC file support
- [ ] Plugin system

---

⚠ Limitations

- No UDP support
- No DNS tunneling
- Experimental DPI features
- Free proxies are unreliable
- Not intended as a VPN replacement

---

🤝 Contributing

Contributions, issues and feature requests are welcome.

If you have ideas for improving performance, reliability or proxy handling, feel free to open an issue or submit a pull request.

---

📜 License

MIT License

---

<div align="center">Made with ❤️ and ☕ by CornVPN

</div>
