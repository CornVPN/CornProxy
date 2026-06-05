# CornProxy
[![License Badge](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Compatibility](https://img.shields.io/badge/python-3-brightgreen.svg)](PROJECT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity)
[![Open Source Love](https://badges.frapsoft.com/os/v3/open-source.svg?v=102)](https://github.com/ellerbrock/open-source-badge/)
```
«High-performance local HTTP/SOCKS proxy engine with traffic observability, proxy pooling, and extensible routing pipeline.»
```
---

Overview

CornProxy is a local proxy orchestration layer designed for routing HTTP and SOCKS traffic through dynamic upstream proxy pools with real-time observability.

It provides:

- L7 HTTP proxy handling (CONNECT + standard requests)
- SOCKS4 / SOCKS5 upstream support
- Proxy pool orchestration with health checking
- Traffic telemetry (per-host / global)
- Terminal-based observability dashboard
```
«⚠️ CornProxy is an experimental networking tool intended for research and educational use.»
```
---

Architecture
```
+---------------------------+
| Client Applications       |
| (Browser / Apps / Tools)  |
+------------+--------------+
             |
             v
+---------------------------+
| CornProxy Local Engine    |
| - HTTP parser             |
| - SOCKS dispatcher        |
| - DPI modifiers (opt.)    |
| - Traffic telemetry       |
+------------+--------------+
             |
             v
+---------------------------+
| Proxy Pool Layer          |
| - HTTP proxies            |
| - SOCKS4 / SOCKS5         |
| - Health validation       |
| - Round-robin scheduler   |
+------------+--------------+
             |
             v
+---------------------------+
| Upstream Network          |
| (Target services)         |
+---------------------------+
```
---

Key Capabilities

Proxy Engine
```
- HTTP/1.1 proxy request parsing
- CONNECT tunneling for HTTPS
- SOCKS4 / SOCKS5 upstream forwarding
- Direct mode (no upstream dependency)
```
Proxy Pool System

- File-based proxy ingestion
- Web-based proxy discovery
- Active health validation
- Round-robin selection strategy
- Dead proxy eviction

Observability

- Real-time traffic metrics:
  - bytes sent / received
  - active connections
  - per-host aggregation
- Live terminal dashboard (Rich UI)
- Historical CSV export

Experimental Traffic Manipulation Layer

- Header case randomization ("random_case")
- Noise injection ("noise")
- Basic packet fragmentation emulation ("fragment")

---

Data Flow

Client Request
      ↓
HTTP Parser (CONNECT / HTTP)
      ↓
Routing Decision Engine
      ↓
Proxy Pool Scheduler
      ↓
Upstream Proxy Selection
      ↓
Socket Tunnel / Forwarding Layer
      ↓
Target Server Response
      ↓
Telemetry Collector

---

Installation
```
git clone https://github.com/CornVPN/cornproxy.git
cd cornproxy
pip install -r requirements.txt
```
```
Dependencies

rich
pysocks
plotext
pyfiglet
colorama
requests
beautifulsoup4
lxml
```
---

Configuration

Default runtime configuration:
```
LISTEN_ADDRESS = 127.0.0.1
LISTEN_PORT    = 8888
MODE            = direct | manual | pool
DPI_MODE        = off | fragment | random_case | noise
```

Proxy format:

http://user:pass@ip:port
socks5://ip:port
socks4://ip:port

---

Runtime Modes

Direct Mode

No upstream proxy is used.

Client → CornProxy → Target

Used for:

- traffic inspection
- debugging
- baseline measurements

---

Manual Proxy Mode

Single upstream proxy.

Client → CornProxy → Proxy → Target

---

Proxy Pool Mode

Dynamic upstream selection.

Client → CornProxy → Proxy Pool → Selected Proxy → Target

Features:

- rotation
- validation
- failure removal

---

Observability

CornProxy exposes real-time metrics:

- Total throughput
- Per-host traffic distribution
- Active connection count
- Speed graph (bytes/sec)
- Proxy pool health

All metrics are rendered via terminal UI dashboard.

---

Limitations

- No UDP support
- No DNS tunneling layer
- No TLS interception (no MITM)
- Experimental DPI layer (non-production)
- Proxy quality depends on external sources

---

Security Model

CornProxy does not perform TLS decryption and does not modify encrypted payloads.

Security considerations:

- Traffic may pass through third-party proxies
- Proxy trust is external responsibility
- No built-in authentication layer

---

Performance Notes

- Multi-threaded per-connection model
- Blocking socket I/O
- No async runtime (no event loop)
- Optimized for simplicity, not throughput

---

Use Cases

- Network protocol education
- Proxy behavior analysis
- Traffic routing experiments
- Debugging HTTP/SOCKS flows
- Observability tooling for proxy chains

---

Project Status

«Experimental — not production-ready»

CornProxy is actively evolving and may contain incomplete or unstable subsystems.

---

License

MIT

---

Disclaimer

This project is intended for educational and research purposes only.
Users are responsible for compliance with applicable laws and network policies.
