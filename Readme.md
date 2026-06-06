<div align="center">

# 🌽 CornProxy

**High-performance local HTTP/SOCKS proxy engine with traffic monitoring and proxy pooling**
<div align="center">

<div align="center">

<a href="https://pay.cloudtips.ru/p/f5d061ac" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important; width: 210px !important;" ></a>
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![Issues](https://img.shields.io/github/issues/CornVPN/CornProxy?style=for-the-badge)](https://github.com/CornVPN/CornProxy/issues)
![Status](https://img.shields.io/badge/status-experimental-orange?style=for-the-badge)

Lightweight local proxy engine for HTTP and SOCKS traffic with proxy pools, traffic observability, and experimental DPI evasion techniques.

</div>

---

### ✨ Features

* 🌐 **HTTP proxy support** & 🔒 **HTTPS CONNECT tunneling**
* ⚡ **SOCKS4 / SOCKS5 support**
* 🔄 **Proxy pool** with automatic rotation
* 📊 **Real-time traffic monitoring** & per-host statistics
* 📈 **Terminal dashboard** powered by `Rich` + `Plotext`
* 📝 **CSV logging** for traffic analysis
* 🧪 **Experimental DPI evasion modes**
* 🎓 **Educational and research oriented**

---

### 🏗 Architecture

```text
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

```
### 🚀 Quick Start
**1. Clone the repository:**
```bash
git clone https://github.com/CornVPN/CornProxy.git
cd CornProxy

```
**2. Install dependencies:**
```bash
pip install -r requirements.txt

```
**3. Run the engine:**
```bash
python cornproxy.py

```
### ⚙ Modes
 * **Direct Mode:** Client → CornProxy → Target
 * **Manual Proxy Mode:** Client → CornProxy → Proxy → Target
 * **Proxy Pool Mode:** Client → CornProxy → Proxy Pool → Target
### 📊 Dashboard
The built-in TUI dashboard provides:
 * Live upload / download speed graphs
 * Active connections counter
 * Real-time proxy pool status
 * Per-host traffic and performance analysis
### 🧪 DPI Modes
| Mode | Description |
|---|---|
| off | DPI evasion disabled |
| fragment | Basic TCP packet fragmentation |
| random_case | HTTP header case randomization |
| noise | Extra junk header injection |
> ⚠ **Note:** DPI features are highly experimental and intended for research purposes.
> 
### 🗺 Roadmap
 * [x] HTTP proxy support
 * [x] SOCKS4 / SOCKS5 support
 * [x] Proxy pool rotation
 * [x] Traffic statistics & CSV logging
 * [x] TUI dashboard
 * [ ] Async architecture rewrite
 * [ ] YAML configuration support
 * [ ] IPv6 support
 * [ ] Docker deployment
 * [ ] PAC file support
 * [ ] Plugin system
### ⚠ Limitations
 * No UDP traffic routing
 * No DNS tunneling/hijacking
 * Experimental DPI mechanics may not bypass advanced firewalls
 * Public proxy pools can be unstable
 * **Not a replacement for a full-scale VPN**
### 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page if you want to submit a pull request or suggest performance optimizations.
### 📜 License
Distributed under the MIT License. See LICENSE for more information.
<div align="center">
          ### ☕ Support the Project

If CornProxy helped you bypass restrictions or optimize your network, feel free to support development:

| Asset | Network | Address |
| :--- | :--- | :--- |
| **USDT** | TRC-20 | `0xe38e6110fc3486568b3c804f6f1bbf67c24b1f61` |
| **TON** | TON | `UQAPN-Xf5AO8wTkoLOjjeu7VdV6mO5jpcKYSidRptS2VkETA` |
| **BTC** | Bitcoin | `bc1qahzfjpyz22twj3524pwjxa4v9ucu9fdz0sjfma` |

Made with ❤️ and ☕ by CornVPN
          
</div>
