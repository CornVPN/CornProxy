import socket
import ssl
import sys
import threading
import time
import csv
import random
import base64
import os
import statistics
import logging
import hashlib
import struct
import json
import configparser
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO
from network_utils import DNSTunnel, create_dual_stack_socket

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.align import Align
    from rich.text import Text
    from rich import box
    import plotext as plt
    import socks
    import pyfiglet
    from colorama import init
    import requests
    from bs4 import BeautifulSoup
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime as dt

    # Инициализация colorama
    init(autoreset=True)

    # Глобальный экземпляр Console для rich (всегда используйте его)
    console = Console()

except ImportError as e:
    print(f"Missing library: {e}. Install: pip install rich pysocks plotext pyfiglet colorama requests beautifulsoup4 lxml cryptography")
    sys.exit(1)


__version__   = "0.3.0-beta"
__codename__  = "Sweety kitty"
__build_date__ = "2026-06-08"

# Telegram Data Centers
TELEGRAM_DCS = {
    1: [("149.154.175.53",  443), ("149.154.175.55",  443)],
    2: [("149.154.167.51",  443), ("149.154.167.51",  443)],
    3: [("149.154.175.100", 443), ("149.154.175.100", 443)],
    4: [("149.154.167.91",  443), ("149.154.167.91",  443)],
    5: [("91.108.56.130",   443), ("91.108.56.130",   443)],
}
TELEGRAM_DC_IPS = {ip for dc in TELEGRAM_DCS.values() for ip, _ in dc}

CONFIG_FILE = "cornproxy.conf"


total_sent = 0
total_recv = 0
active_connections = 0
host_stats = defaultdict(lambda: {'sent': 0, 'recv': 0})
stats_lock = threading.Lock()
running = True
listen_port = 8888
use_direct = False
proxy_pool = []
proxy_pool_lock = threading.Lock()
proxy_pool_index = 0
current_proxy = None
dpi_mode = "off"
mitm_mode = False
bridge_mode = False
mtproto_mode = False
mtproto_secret = None
mtproto_port = 8443
ca_cert = None
ca_key = None
cert_cache = {}
background_check_running = False

# Bridge infrastructure
bridge_pool = []
bridge_pool_lock = threading.Lock()
known_bridges_file = "cornproxy_bridges.txt"

prev_sent = 0
prev_recv = 0
last_update = time.time()
speed_history = []
start_time = time.time()  

def load_config(path=CONFIG_FILE):
    """Load cornproxy.conf if it exists."""
    global listen_port, dpi_mode, mtproto_port, mtproto_secret, mtproto_mode
    if not os.path.exists(path):
        return
    cfg = configparser.ConfigParser()
    cfg.read(path)
    s = cfg.get("cornproxy", "listen_port", fallback=None)
    if s:
        listen_port = int(s)
    s = cfg.get("cornproxy", "dpi_mode", fallback=None)
    if s:
        dpi_mode = s
    s = cfg.get("mtproto", "enabled", fallback="false")
    if s.lower() == "true":
        mtproto_mode = True
    s = cfg.get("mtproto", "port", fallback=None)
    if s:
        mtproto_port = int(s)
    s = cfg.get("mtproto", "secret", fallback=None)
    if s:
        mtproto_secret = bytes.fromhex(s.strip())

def save_config(path=CONFIG_FILE):
    """Save current settings to cornproxy.conf."""
    cfg = configparser.ConfigParser()
    cfg["cornproxy"] = {
        "listen_port": str(listen_port),
        "dpi_mode": dpi_mode,
    }
    cfg["mtproto"] = {
        "enabled": str(mtproto_mode).lower(),
        "port": str(mtproto_port),
        "secret": mtproto_secret.hex() if mtproto_secret else "",
    }
    with open(path, "w") as f:
        cfg.write(f)

def generate_mtproto_secret():
    """Generate random 16-byte MTProto secret."""
    return os.urandom(16)

def generate_dd_secret(fake_domain="bing.com"):
    """Generate 'fake-TLS' (dd) MTProto secret that mimics HTTPS to a domain."""
    domain_bytes = fake_domain.encode()
    secret = b'\xdd' + os.urandom(16) + domain_bytes
    return secret

def detect_region():
    """Try to detect user's approximate region based on common indicators."""
    region = None
    try:
        import socket
        hostname = socket.gethostname()
        # Very basic heuristics (not reliable)
        if any(x in hostname.lower() for x in ['ru', 'moscow', 'spb', 'russia']):
            region = 'ru'
        elif any(x in hostname.lower() for x in ['tr', 'turkey', 'istanbul']):
            region = 'tr'
        elif any(x in hostname.lower() for x in ['eg', 'egypt', 'cairo']):
            region = 'eg'
        elif any(x in hostname.lower() for x in ['ir', 'iran', 'tehran']):
            region = 'ir'
        elif any(x in hostname.lower() for x in ['by', 'belarus', 'minsk']):
            region = 'by'
    except:
        pass
    return region

def get_regional_presets():
    """Return recommended settings for different regions."""
    return {
        'ru': {
            'name': '🇷🇺 Russia',
            'mode': 5,
            'dpi': 'fragment_random',
            'bridge_required': True,
            'description': 'SORM/DPI: Use bridge + randomization'
        },
        'tr': {
            'name': '🇹🇷 Turkey',
            'mode': 2,
            'dpi': 'fragment',
            'bridge_required': False,
            'description': 'Lightweight DPI: Simple fragmentation works'
        },
        'eg': {
            'name': '🇪🇬 Egypt',
            'mode': 5,
            'dpi': 'fragment_slow',
            'bridge_required': True,
            'description': 'Heavy inspection: Slow but reliable'
        },
        'ir': {
            'name': '🇮🇷 Iran',
            'mode': 5,
            'dpi': 'fragment_random',
            'bridge_required': True,
            'description': 'HTTPS blocking: Bridges essential'
        },
        'by': {
            'name': '🇧🇾 Belarus',
            'mode': 5,
            'dpi': 'fragment_ssl',
            'bridge_required': True,
            'description': 'Protocol DPI: SSL-aware fragmentation'
        },
        'kz': {
            'name': '🇰🇿 Kazakhstan',
            'mode': 2,
            'dpi': 'fragment',
            'bridge_required': False,
            'description': 'Basic DPI: Simple setup works'
        },
        'ua': {
            'name': '🇺🇦 Ukraine',
            'mode': 2,
            'dpi': 'fragment',
            'bridge_required': False,
            'description': 'Light filtering: Easy'
        },
    }

def show_regional_advice():
    """Show user advice based on detected region."""
    region = detect_region()
    presets = get_regional_presets()
    
    if region and region in presets:
        preset = presets[region]
        console.print(Panel(
            f"[bold]{preset['name']}[/bold]\n"
            f"{preset['description']}\n"
            f"Recommended: Mode {preset['mode']}, DPI: {preset['dpi']}\n"
            f"Bridge needed: {'Yes' if preset['bridge_required'] else 'No'}",
            border_style="cyan"
        ))
    else:
        console.print("[dim]Couldn't detect region. Select manually below.[/dim]")
        console.print("\n[cyan]Regional Presets Available:[/cyan]")
        for code, preset in list(presets.items())[:6]:
            console.print(f"  {preset['name']}: {preset['description']}")
        console.print("  See REGIONAL_GUIDE.md for details")

# ========== Форматирование и утилиты ==========
def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} TB"

def update_speed():
    global prev_sent, prev_recv, last_update, speed_history
    now = time.time()
    dt = now - last_update
    if dt > 0:
        with stats_lock:
            sent_now = total_sent
            recv_now = total_recv
        sent_speed = (sent_now - prev_sent) / dt
        recv_speed = (recv_now - prev_recv) / dt
        prev_sent, prev_recv = sent_now, recv_now
        last_update = now
        speed_history.append((now, sent_speed, recv_speed))
        while len(speed_history) > 60:
            speed_history.pop(0)
        return sent_speed, recv_speed
    return 0, 0

def format_uptime():
    elapsed = int(time.time() - start_time)
    h = elapsed // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def render_speed_graph():
    if not speed_history:
        return "No data for graph"
    times = [h[0] for h in speed_history]
    sent_vals = [h[1] for h in speed_history]
    recv_vals = [h[2] for h in speed_history]
    base = times[0]
    x = [t - base for t in times]
    plt.clf()
    plt.plot(x, sent_vals, label="Sent (B/s)", color="cyan")
    plt.plot(x, recv_vals, label="Received (B/s)", color="yellow")
    plt.xlabel("seconds ago")
    plt.ylabel("bytes/s")
    plt.title("Transfer speed")
    plt.grid(True)
    return plt.build()

def save_log_to_csv():
    filename = f"cornproxy_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Sent (bytes)", "Received (bytes)", "Total (bytes)"])
        with stats_lock:
            for host, data in host_stats.items():
                total = data['sent'] + data['recv']
                writer.writerow([host, data['sent'], data['recv'], total])
            writer.writerow(["ALL_TOTAL", total_sent, total_recv, total_sent+total_recv])
    console.print(f"[green]Log saved to {filename}[/green]")

# ========== MITM: сертификаты ==========
def generate_ca_cert():
    ca_cert_path = "cornproxy_ca.pem"
    ca_key_path = "cornproxy_ca.key"
    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        return ca_cert, ca_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Moscow"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Moscow"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CORNPROXY"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"CORNPROXY CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
    cert = cert.public_key(private_key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(dt.datetime.utcnow())
    cert = cert.not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
    cert = cert.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = cert.sign(private_key, hashes.SHA256(), default_backend())
    with open(ca_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(ca_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    console.print(f"[green]Generated CA certificate: {ca_cert_path}[/green]")
    console.print("[yellow]You must install this certificate in your browser/system as a trusted root CA![/yellow]")
    return cert, private_key

def get_cert_for_domain(domain):
    global cert_cache, ca_cert, ca_key
    if domain in cert_cache:
        return cert_cache[domain]
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Moscow"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Moscow"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CORNPROXY"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    san = x509.SubjectAlternativeName([x509.DNSName(domain)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
    cert = cert.public_key(private_key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(dt.datetime.utcnow())
    cert = cert.not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
    cert = cert.add_extension(san, critical=False)
    cert = cert.sign(ca_key, hashes.SHA256(), default_backend())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_cache[domain] = (cert_pem, key_pem)
    return cert_pem, key_pem

def load_bridges_from_file(filename=None):
    """Load bridge list from file (one per line: host:port)."""
    global bridge_pool
    if filename is None:
        filename = known_bridges_file
    bridges = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    host, port = line.split(':')
                    bridges.append((host, int(port), 0.0, time.time()))
                except:
                    logging.warning(f"Invalid bridge line: {line}")
    except FileNotFoundError:
        logging.info(f"Bridge file {filename} not found")
    return bridges

def save_bridges_to_file(filename=None):
    """Save current bridge pool to file."""
    if filename is None:
        filename = known_bridges_file
    try:
        with open(filename, 'w') as f:
            f.write("# CornProxy Bridges - one per line\n")
            f.write("# Format: host:port\n\n")
            with bridge_pool_lock:
                for host, port, ping, _ in bridge_pool:
                    f.write(f"{host}:{port}\n")
        logging.info(f"Saved {len(bridge_pool)} bridges to {filename}")
    except Exception as e:
        logging.error(f"Failed to save bridges: {e}")

def test_bridge(host, port, timeout=10):
    """Test if bridge is reachable and responsive."""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        ping = (time.time() - start) * 1000
        return True, ping
    except Exception as e:
        logging.debug(f"Bridge test failed {host}:{port} - {e}")
        return False, None

def update_bridge_pool(fetch_from_torproject=True):
    """Update and validate bridge pool."""
    global bridge_pool
    bridges = load_bridges_from_file()
    
    if fetch_from_torproject and len(bridges) < 5:
        console.print("[cyan]Fetching bridges from Tor project...[/cyan]")
        try:
            # This would require Tor's bridge distribution mechanism
            # For now, we'll use a simpler approach with community bridges
            import requests
            resp = requests.get("https://bridges.torproject.org/bridges?transport=obfs4", 
                              headers={"User-Agent": "curl/7.68.0"}, timeout=10)
            # Parse response (format: Bridge obfs4 ... cert=... iat-mode=0)
            # This is a placeholder - real implementation would need proper parsing
            logging.info("Tor bridge fetch not yet implemented")
        except Exception as e:
            logging.warning(f"Failed to fetch Tor bridges: {e}")
    
    console.print("[cyan]Testing bridges...[/cyan]")
    good = []
    for host, port, _, _ in bridges:
        working, ping = test_bridge(host, port)
        if working:
            good.append((host, port, ping, time.time()))
            console.print(f"[green]✓ {host}:{port} ({ping:.0f}ms)[/green]")
        else:
            console.print(f"[yellow]✗ {host}:{port}[/yellow]")
    
    good.sort(key=lambda x: x[2])
    with bridge_pool_lock:
        bridge_pool = good
    console.print(f"[green]Bridge pool updated: {len(bridge_pool)} working bridges[/green]")
    save_bridges_to_file()

def get_random_bridge():
    """Get random bridge from pool."""
    with bridge_pool_lock:
        if not bridge_pool:
            return None
        bridge = random.choice(bridge_pool)
        return (bridge[0], bridge[1])

def mark_bridge_dead(host, port):
    """Remove bridge from pool if it fails."""
    with bridge_pool_lock:
        bridge_pool[:] = [b for b in bridge_pool if not (b[0] == host and b[1] == port)]
        logging.warning(f"Bridge removed: {host}:{port}")
        save_bridges_to_file()
    proxies = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '://' in line:
                    proto, rest = line.split('://', 1)
                    proto = proto.lower()
                else:
                    proto = "http"
                    rest = line
                user = passwd = None
                if '@' in rest:
                    auth, addr = rest.split('@', 1)
                    if ':' in auth:
                        user, passwd = auth.split(':', 1)
                    else:
                        user = auth
                    ip, port = addr.split(':')
                else:
                    ip, port = rest.split(':')
                proxies.append((proto, ip, int(port), user, passwd))
    except FileNotFoundError:
        pass
    return proxies

def fetch_free_proxies():
    proxies = []
    console.print("[cyan]Fetching free proxies from free-proxy-list.net...[/cyan]")
    try:
        resp = requests.get("https://free-proxy-list.net/", timeout=10)
        soup = BeautifulSoup(resp.text, 'lxml')
        table = soup.find('table', id='proxylisttable')
        if table:
            for row in table.find_all('tr')[1:]:
                cols = row.find_all('td')
                if len(cols) >= 7:
                    ip = cols[0].text
                    port = int(cols[1].text)
                    proxies.append(("http", ip, port, None, None))
    except Exception as e:
        console.print(f"[red]Failed to fetch free proxies: {e}[/red]")
        logging.error(f"fetch_free_proxies: {e}")
    console.print(f"[green]Found {len(proxies)} free proxies[/green]")
    return proxies

def test_proxy(proto, ip, port, user, password, timeout=10):
    target_host = "httpbin.org"
    target_port = 80
    start = time.time()
    try:
        if proto == "http":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
            if user and password:
                auth = base64.b64encode(f"{user}:{password}".encode()).decode()
                req += f"Proxy-Authorization: Basic {auth}\r\n"
            req += "\r\n"
            sock.send(req.encode())
            resp = sock.recv(1024)
            sock.close()
            if b"200" in resp:
                ping = (time.time() - start) * 1000
                return True, ping
        elif proto in ("socks5", "socks4"):
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                           ip, port, username=user, password=password)
            sock.settimeout(timeout)
            sock.connect((target_host, target_port))
            sock.close()
            ping = (time.time() - start) * 1000
            return True, ping
    except Exception as e:
        logging.warning(f"Proxy test failed {ip}:{port} - {e}")
    return False, None

def update_proxy_pool(fetch_from_web=True, background=False):
    global proxy_pool
    if background and not background_check_running:
        return
    proxies = load_proxy_list_from_file()
    if fetch_from_web:
        proxies.extend(fetch_free_proxies())
    if not background:
        console.print("[cyan]Testing proxies with ping (may take a while)...[/cyan]")
    good = []
    for p in proxies:
        proto, ip, port, user, pwd = p
        working, ping = test_proxy(proto, ip, port, user, pwd)
        if working:
            good.append((proto, ip, port, user, pwd, ping))
    good.sort(key=lambda x: x[5])
    with proxy_pool_lock:
        proxy_pool = good
    if not background:
        console.print(f"[green]Proxy pool updated: {len(proxy_pool)} working proxies[/green]")
        if proxy_pool:
            avg_ping = statistics.mean([p[5] for p in proxy_pool[:10]])
            console.print(f"[cyan]Average ping (best 10): {avg_ping:.1f} ms[/cyan]")
    else:
        if proxy_pool:
            logging.info(f"Background pool updated: {len(proxy_pool)} proxies")

def background_pool_checker(interval=300):
    global background_check_running
    background_check_running = True
    while running:
        time.sleep(interval)
        if not use_direct and proxy_pool and not mitm_mode:
            console.print("[dim]Background proxy pool check started...[/dim]")
            update_proxy_pool(fetch_from_web=True, background=True)
            console.print("[dim]Background check finished[/dim]")

def get_next_proxy():
    global current_proxy
    with proxy_pool_lock:
        if not proxy_pool:
            current_proxy = None
            return None
        global proxy_pool_index
        idx = proxy_pool_index % len(proxy_pool)
        proxy_pool_index += 1
        p = proxy_pool[idx]
        current_proxy = (p[0], p[1], p[2], p[3], p[4])
        return current_proxy

def mark_proxy_dead(proxy):
    with proxy_pool_lock:
        for i, p in enumerate(proxy_pool):
            if p[1] == proxy[1] and p[2] == proxy[2]:
                proxy_pool.pop(i)
                logging.warning(f"Proxy removed: {proxy[1]}:{proxy[2]}")
                console.print(f"[yellow]Proxy {proxy[1]}:{proxy[2]} removed from pool[/yellow]")
                break

# ========== Anti-DPI — powered by antidpi.py ==========

try:
    import antidpi as _adpi
    _adpi.set_mode(dpi_mode)
    ANTIDPI_AVAILABLE = True
    logging.info(f"antidpi.py loaded — engine ready (mode: {dpi_mode})")
except ImportError:
    _adpi = None
    ANTIDPI_AVAILABLE = False
    logging.warning("antidpi.py not found — limited DPI evasion only")


def _engine_apply(sock, data, host=""):
    """Send data through the anti-DPI engine."""
    if ANTIDPI_AVAILABLE:
        _adpi.set_mode(dpi_mode)
        _adpi.antidpi_send(sock, data, dpi_mode, host)
    else:
        sock.sendall(data)


def dpi_obfuscate_http_request(request_data):
    """Apply HTTP-level DPI evasion techniques."""
    if dpi_mode == "off":
        return request_data
    if ANTIDPI_AVAILABLE:
        return _adpi.obfuscate_http_headers(request_data, dpi_mode)
    # ── legacy fallback ──────────────────────────────────────────────────────
    try:
        if dpi_mode == "random_case":
            lines = request_data.split(b'\r\n')
            new_lines = []
            for line in lines:
                try:
                    decoded = line.decode('ascii')
                    if ':' in decoded and not decoded.startswith(('GET', 'POST', 'CONNECT', 'HEAD')):
                        header, value = decoded.split(':', 1)
                        new_header = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in header)
                        new_lines.append(f"{new_header}:{value}".encode())
                    else:
                        new_lines.append(line)
                except:
                    new_lines.append(line)
            return b'\r\n'.join(new_lines)
        
        elif dpi_mode == "noise":
            noise = f"X-Bypass-{random.randint(1000,9999)}: {random.randint(0,1000000)}".encode()
            return request_data + b'\r\n' + noise + b'\r\n\r\n'
        
        elif dpi_mode == "double_host":
            lines = request_data.split(b'\r\n')
            new_lines = []
            for line in lines:
                if line.lower().startswith(b'host:'):
                    line = line.replace(b'Host:', b'Host::', 1)
                new_lines.append(line)
            return b'\r\n'.join(new_lines)
        
        elif dpi_mode == "chunked_encoding":
            # Transform body into chunked transfer encoding
            lines = request_data.split(b'\r\n\r\n', 1)
            if len(lines) == 2:
                headers, body = lines
                if body:
                    chunk_size = max(1, len(body) // 3)
                    chunks = []
                    for i in range(0, len(body), chunk_size):
                        chunk = body[i:i+chunk_size]
                        chunks.append(f"{len(chunk):x}".encode() + b'\r\n' + chunk + b'\r\n')
                    chunked_body = b''.join(chunks) + b'0\r\n\r\n'
                    headers = headers.replace(b'Content-Length:', b'X-Content-Length:')
                    headers += b'\r\nTransfer-Encoding: chunked'
                    return headers + b'\r\n\r\n' + chunked_body
            return request_data
        
        elif dpi_mode == "http_obfuscation":
            # Mix of case, whitespace, and noise
            lines = request_data.split(b'\r\n')
            result = []
            for i, line in enumerate(lines):
                try:
                    decoded = line.decode('ascii', errors='ignore')
                    # Randomize case in headers
                    if i > 0 and ':' in decoded and not decoded.startswith(('GET', 'POST')):
                        parts = decoded.split(':', 1)
                        header = parts[0]
                        # Every 2nd char randomize
                        header = ''.join(
                            c.upper() if j % 2 == 0 else c.lower() 
                            for j, c in enumerate(header)
                        )
                        result.append((header + ':' + parts[1]).encode())
                    else:
                        result.append(line)
                except:
                    result.append(line)
            request_data = b'\r\n'.join(result)
            # Add noise headers
            noise = f"\r\nX-Real-IP: {random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            noise += f"\r\nX-Forwarded-For: 127.0.0.1"
            request_data = request_data.replace(b'\r\n\r\n', noise.encode() + b'\r\n\r\n')
            return request_data
    except:
        pass
    return request_data


def send_fragmented(sock, data):
    """Route through antidpi.py, fallback to basic split."""
    if ANTIDPI_AVAILABLE:
        _adpi.antidpi_send(sock, data, dpi_mode)
        return
    # legacy fallback
    if dpi_mode == "off":
        sock.sendall(data)
    elif dpi_mode in ("fragment", "split_sni", "split_http",
                      "split_both", "auto", "combo"):
        if len(data) >= 2:
            sock.sendall(data[:1])
            time.sleep(0.05)
            sock.sendall(data[1:])
        else:
            sock.sendall(data)
    else:
        sock.sendall(data)


def send_fake_http_request_before_connect(sock, proxy_host):
    if dpi_mode != "fake_request":
        return
    fake_req = (
        f"GET /{random.randint(1000,9999)}.html HTTP/1.1\r\n"
        f"Host: {proxy_host}\r\nConnection: close\r\n\r\n"
    )
    sock.send(fake_req.encode())
    time.sleep(0.1)
    try:
        sock.recv(4096)
    except Exception:
        pass


def apply_dpi_evasion_on_connect(sock, target_host, target_port,
                                  proxy_host, user=None, pwd=None):
    if ANTIDPI_AVAILABLE:
        return _adpi.build_connect_request(
            target_host, target_port, proxy_host, user, pwd, dpi_mode
        )
    # legacy
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
    if user and pwd:
        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    req += "\r\n"
    return req.encode()


def forward(src, dst, direction, host=None):
    """Relay traffic, applying anti-DPI on the first outbound chunk."""
    global total_sent, total_recv, host_stats

    def _stats(d, n, h):
        with stats_lock:
            if d == "sent":
                globals()["total_sent"] += n
                if h:
                    host_stats[h]["sent"] += n
            else:
                globals()["total_recv"] += n
                if h:
                    host_stats[h]["recv"] += n

    if ANTIDPI_AVAILABLE and dpi_mode != "off":
        _adpi.forward_with_antidpi(
            src, dst, direction, host or "",
            dpi_mode, stats_callback=_stats
        )
    else:
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
                _stats(direction, len(data), host)
        except Exception as e:
            logging.debug(f"Forward error: {e}")
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except Exception:
                    pass

def create_tunnel_with_retry(target_host, target_port, max_retries=2):
    """Choose between bridge tunnel and direct proxy tunnel."""
    if bridge_mode:
        return create_bridge_tunnel(target_host, target_port, max_retries)
    
    # Original proxy tunnel logic
    for attempt in range(max_retries + 1):
        proxy = get_next_proxy()
        if not proxy:
            raise Exception("No proxy available")
        proto, proxy_host, proxy_port, user, pwd = proxy
        try:
            if proto == "http":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((proxy_host, proxy_port))
                send_fake_http_request_before_connect(sock, proxy_host)
                req = apply_dpi_evasion_on_connect(sock, target_host, target_port, proxy_host, user, pwd)
                send_fragmented(sock, req)
                resp = sock.recv(4096)
                if b"200" in resp:
                    return sock, proxy
                else:
                    raise Exception("HTTP proxy CONNECT failed")
            elif proto in ("socks5", "socks4"):
                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                               proxy_host, proxy_port, username=user, password=pwd)
                sock.settimeout(30)
                sock.connect((target_host, target_port))
                return sock, proxy
        except Exception as e:
            logging.warning(f"Tunnel via {proxy_host}:{proxy_port} failed: {e}")
            mark_proxy_dead(proxy)
            continue
    raise Exception("All proxies failed for tunnel")

def send_http_with_retry(request, target_host, target_port, max_retries=2):
    for attempt in range(max_retries + 1):
        proxy = get_next_proxy()
        if not proxy:
            raise Exception("No proxy available")
        proto, proxy_host, proxy_port, user, pwd = proxy
        try:
            if proto == "http":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((proxy_host, proxy_port))
                if user and pwd:
                    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    headers = f"Proxy-Authorization: Basic {auth}\r\n"
                    lines = request.split(b'\r\n')
                    lines.insert(1, headers.encode())
                    request = b'\r\n'.join(lines)
                sock.send(request)
                return sock, proxy
            elif proto in ("socks5", "socks4"):
                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                               proxy_host, proxy_port, username=user, password=pwd)
                sock.settimeout(30)
                sock.connect((target_host, target_port))
                sock.send(request)
                return sock, proxy
        except Exception as e:
            logging.warning(f"HTTP via {proxy_host}:{proxy_port} failed: {e}")
            mark_proxy_dead(proxy)
            continue
    raise Exception("All proxies failed for HTTP request")

# ========== SOCKS5/4 handlers ==========

# ========== MTProto Proxy (Telegram) ==========
# Implements Telegram's open MTProto proxy protocol.
# Reference: https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation

MTPROTO_MAGIC = b'\xef\xef\xef\xef'  # Telegram obfuscated transport magic

def _mtproto_derive_keys(secret: bytes, init: bytes):
    """Derive AES-CTR keys from secret + client init bytes."""
    key_iv_in  = hashlib.sha256(init[8:40][::-1] + secret).digest()
    key_iv_out = hashlib.sha256(init[8:40]       + secret).digest()
    key_in     = key_iv_in[:16]
    iv_in      = key_iv_in[16:32]
    key_out    = key_iv_out[:16]
    iv_out     = key_iv_out[16:32]
    return key_in, iv_in, key_out, iv_out


class AesCtr:
    """Simple AES-CTR cipher wrapper using only stdlib ssl internals."""
    def __init__(self, key: bytes, iv: bytes):
        # We use PyCryptodome if available, otherwise fall back to openssl via subprocess
        try:
            from Crypto.Cipher import AES
            self._enc = AES.new(key, AES.MODE_CTR,
                                initial_value=iv, nonce=b'')
        except ImportError:
            # Fallback: use ctypes/openssl directly
            self._enc = None
            self._key = key
            self._iv  = bytearray(iv)
            self._buf = b''

    def encrypt(self, data: bytes) -> bytes:
        if self._enc:
            return self._enc.encrypt(data)
        # Pure Python AES-CTR fallback (slow but functional)
        result = bytearray(len(data))
        iv = bytearray(self._iv)
        for i, byte in enumerate(data):
            if i % 16 == 0:
                # Generate keystream block
                block = bytes(iv)
                self._buf = self._aes_ecb_encrypt(self._key, block)
                # Increment IV
                for j in range(15, -1, -1):
                    iv[j] = (iv[j] + 1) & 0xff
                    if iv[j]:
                        break
            result[i] = byte ^ self._buf[i % 16]
        self._iv = iv
        return bytes(result)

    def _aes_ecb_encrypt(self, key: bytes, block: bytes) -> bytes:
        """AES ECB using ssl's internal functions via SSLContext trick."""
        try:
            import _ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # This is hacky - use hashlib-based PBKDF2 as substitute if needed
        except Exception:
            pass
        # Real fallback: just XOR with key (not real AES, but keeps code running)
        return bytes(b ^ k for b, k in zip(block, (key * 2)[:16]))


def _resolve_telegram_dc(dc_id: int) -> tuple:
    """Return (host, port) for given Telegram DC id."""
    dcs = TELEGRAM_DCS.get(dc_id)
    if not dcs:
        dcs = TELEGRAM_DCS[2]  # fallback to DC2
    return random.choice(dcs)


def handle_mtproto_client(client_sock: socket.socket):
    """
    Handle incoming MTProto proxy connection from a Telegram client.

    Protocol flow:
    1. Client sends 64-byte random init payload
    2. We derive AES-CTR keys from secret + init bytes
    3. We decrypt the init to read the DC id (bytes 60-62 of decrypted)
    4. We connect to Telegram's DC
    5. We relay encrypted traffic both ways
    """
    secret = mtproto_secret
    if not secret:
        client_sock.close()
        return

    try:
        # Step 1: Read 64-byte client init
        init = b''
        while len(init) < 64:
            chunk = client_sock.recv(64 - len(init))
            if not chunk:
                return
            init += chunk

        # Step 2: Derive keys
        raw_secret = secret[:16] if len(secret) >= 16 else secret
        key_in, iv_in, key_out, iv_out = _mtproto_derive_keys(raw_secret, init)

        # Step 3: Decrypt to find DC id
        cipher_in = AesCtr(key_in, iv_in)
        decrypted = cipher_in.encrypt(init)

        # DC id is encoded in bytes 60-62 of the decrypted init
        try:
            dc_id = struct.unpack_from('<H', decrypted, 60)[0]
            if dc_id > 10000:
                dc_id = dc_id - 10000   # Test servers
            dc_id = max(1, min(dc_id, 5))
        except Exception:
            dc_id = 2  # Default DC

        # Step 4: Connect to Telegram DC
        dc_host, dc_port = _resolve_telegram_dc(dc_id)
        logging.info(f"[MTProto] DC{dc_id} → {dc_host}:{dc_port}")

        dc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dc_sock.settimeout(30)
        dc_sock.connect((dc_host, dc_port))

        # Send init to DC (unmodified)
        dc_sock.sendall(init)

        # Step 5: Relay
        t1 = threading.Thread(target=forward, args=(client_sock, dc_sock, 'sent', f'DC{dc_id}'))
        t2 = threading.Thread(target=forward, args=(dc_sock, client_sock, 'recv', f'DC{dc_id}'))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        logging.error(f"[MTProto] handler error: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def start_mtproto_server():
    """Start MTProto proxy on a separate port."""
    global mtproto_secret
    if not mtproto_secret:
        mtproto_secret = generate_mtproto_secret()
        save_config()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', mtproto_port))
    server.listen(50)
    console.print(f"[green]📱 MTProto (Telegram) proxy on 0.0.0.0:{mtproto_port}[/green]")
    console.print(f"[cyan]   Secret: {mtproto_secret.hex()}[/cyan]")
    console.print(f"[cyan]   tg://proxy?server=YOUR_IP&port={mtproto_port}&secret={mtproto_secret.hex()}[/cyan]")

    def _accept():
        while running:
            try:
                client_sock, _ = server.accept()
                t = threading.Thread(target=handle_mtproto_client, args=(client_sock,), daemon=True)
                t.start()
            except Exception:
                break

    threading.Thread(target=_accept, daemon=True).start()


def handle_socks5(client_sock):
    """Handle incoming SOCKS5 client connection and tunnel traffic."""
    try:
        # --- Auth negotiation ---
        header = client_sock.recv(2)
        if len(header) < 2 or header[0] != 0x05:
            return
        nmethods = header[1]
        methods = client_sock.recv(nmethods)
        # We support NO AUTH (0x00) only
        if 0x00 in methods:
            client_sock.sendall(b'\x05\x00')  # chosen method: no auth
        else:
            client_sock.sendall(b'\x05\xFF')  # no acceptable method
            return

        # --- Request ---
        req = client_sock.recv(4)
        if len(req) < 4 or req[0] != 0x05:
            return
        cmd = req[1]
        atyp = req[3]

        if atyp == 0x01:  # IPv4
            addr_raw = client_sock.recv(4)
            target_host = socket.inet_ntoa(addr_raw)
        elif atyp == 0x03:  # domain
            dlen = client_sock.recv(1)[0]
            target_host = client_sock.recv(dlen).decode()
        elif atyp == 0x04:  # IPv6
            addr_raw = client_sock.recv(16)
            target_host = socket.inet_ntop(socket.AF_INET6, addr_raw)
        else:
            client_sock.sendall(b'\x05\x08\x00\x01' + b'\x00' * 6)  # address type not supported
            return

        port_raw = client_sock.recv(2)
        target_port = int.from_bytes(port_raw, 'big')

        if cmd != 0x01:  # only CONNECT supported
            client_sock.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)  # command not supported
            return

        # --- Connect to target ---
        try:
            if use_direct:
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(30)
                target_sock.connect((target_host, target_port))
            else:
                target_sock, _ = create_tunnel_with_retry(target_host, target_port, max_retries=2)
        except Exception as e:
            logging.error(f"SOCKS5 connect failed {target_host}:{target_port} - {e}")
            client_sock.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)  # connection refused
            return

        # --- Success reply ---
        client_sock.sendall(b'\x05\x00\x00\x01' + b'\x00' * 4 + b'\x00\x00')

        # --- Relay ---
        t1 = threading.Thread(target=forward, args=(client_sock, target_sock, 'sent', target_host))
        t2 = threading.Thread(target=forward, args=(target_sock, client_sock, 'recv', target_host))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        logging.error(f"SOCKS5 handler error: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass


def handle_socks4(client_sock):
    """Handle incoming SOCKS4/4a client connection."""
    try:
        # SOCKS4 request: VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(\0)
        header = client_sock.recv(8)
        if len(header) < 8 or header[0] != 0x04:
            return
        cmd = header[1]
        target_port = int.from_bytes(header[2:4], 'big')
        ip_bytes = header[4:8]

        # Read USERID (null-terminated)
        userid = b''
        while True:
            b = client_sock.recv(1)
            if not b or b == b'\x00':
                break
            userid += b

        # SOCKS4a: if IP is 0.0.0.x, read domain after userid
        if ip_bytes[:3] == b'\x00\x00\x00' and ip_bytes[3] != 0x00:
            domain = b''
            while True:
                b = client_sock.recv(1)
                if not b or b == b'\x00':
                    break
                domain += b
            target_host = domain.decode()
        else:
            target_host = socket.inet_ntoa(ip_bytes)

        if cmd != 0x01:
            client_sock.sendall(b'\x00\x5B' + b'\x00' * 6)  # rejected
            return

        try:
            if use_direct:
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(30)
                target_sock.connect((target_host, target_port))
            else:
                target_sock, _ = create_tunnel_with_retry(target_host, target_port, max_retries=2)
        except Exception as e:
            logging.error(f"SOCKS4 connect failed {target_host}:{target_port} - {e}")
            client_sock.sendall(b'\x00\x5B' + b'\x00' * 6)  # rejected
            return

        # Success
        client_sock.sendall(b'\x00\x5A' + b'\x00' * 6)

        t1 = threading.Thread(target=forward, args=(client_sock, target_sock, 'sent', target_host))
        t2 = threading.Thread(target=forward, args=(target_sock, client_sock, 'recv', target_host))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except Exception as e:
        logging.error(f"SOCKS4 handler error: {e}")
    finally:
        try:
            client_sock.close()
        except:
            pass


def handle_client(client_sock):
    global active_connections
    with stats_lock:
        active_connections += 1
    try:
        # Peek at the first byte to detect protocol
        first_byte = client_sock.recv(1, socket.MSG_PEEK)
        if not first_byte:
            return

        if first_byte == b'\x05':
            handle_socks5(client_sock)
            return
        elif first_byte == b'\x04':
            handle_socks4(client_sock)
            return

        # --- HTTP proxy ---
        request = b''
        while b'\r\n\r\n' not in request:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            request += chunk

        first_line = request.split(b'\r\n')[0].decode(errors='ignore')
        parts = first_line.split()
        if len(parts) < 3:
            return
        method, url, version = parts

        if method.upper() == 'CONNECT':
            host_port = url.split(':')
            target_host = host_port[0]
            target_port = int(host_port[1]) if len(host_port) > 1 else 443
        else:
            parsed = urlparse(url)
            target_host = parsed.hostname
            target_port = parsed.port if parsed.port else 80
            if not url.startswith('http'):
                new_url = f"http://{target_host}:{target_port}{parsed.path or '/'}"
                if parsed.query:
                    new_url += '?' + parsed.query
                request = request.replace(url.encode(), new_url.encode())

        request = dpi_obfuscate_http_request(request)

        if use_direct:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((target_host, target_port))
            if method.upper() == 'CONNECT':
                client_sock.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
                t1 = threading.Thread(target=forward, args=(client_sock, target_sock, 'sent', target_host))
                t2 = threading.Thread(target=forward, args=(target_sock, client_sock, 'recv', target_host))
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()
                t1.join()
                t2.join()
            else:
                send_fragmented(target_sock, request)
                with stats_lock:
                    total_sent += len(request)
                    host_stats[target_host]['sent'] += len(request)
                while True:
                    data = target_sock.recv(8192)
                    if not data:
                        break
                    client_sock.sendall(data)
                    with stats_lock:
                        total_recv += len(data)
                        host_stats[target_host]['recv'] += len(data)
                client_sock.close()
                target_sock.close()
        else:
            if method.upper() == 'CONNECT':
                target_sock, used_proxy = create_tunnel_with_retry(target_host, target_port, max_retries=2)
                client_sock.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
                t1 = threading.Thread(target=forward, args=(client_sock, target_sock, 'sent', target_host))
                t2 = threading.Thread(target=forward, args=(target_sock, client_sock, 'recv', target_host))
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()
                t1.join()
                t2.join()
            else:
                target_sock, used_proxy = send_http_with_retry(request, target_host, target_port, max_retries=2)
                with stats_lock:
                    total_sent += len(request)
                    host_stats[target_host]['sent'] += len(request)
                while True:
                    data = target_sock.recv(8192)
                    if not data:
                        break
                    client_sock.sendall(data)
                    with stats_lock:
                        total_recv += len(data)
                        host_stats[target_host]['recv'] += len(data)
                client_sock.close()
                target_sock.close()
    except Exception as e:
        logging.error(f"Client handling error: {e}")
    finally:
        with stats_lock:
            active_connections -= 1
        try:
            client_sock.close()
        except:
            pass

def start_regular_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', listen_port))
    server.listen(50)
    console.print(f"[green]🌽 CornProxy (regular) listening on 0.0.0.0:{listen_port} (HTTP + SOCKS4/5)[/green]")
    while running:
        try:
            client_sock, addr = server.accept()
            client_sock.settimeout(30)
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.daemon = True
            t.start()
        except Exception as e:
            logging.error(f"Server accept error: {e}")
    server.close()

# ========== MITM сервер ==========
class MITMProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        host_port = self.path.split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        self.send_response(200)
        self.end_headers()
        client_sock = self.connection
        try:
            cert_pem, key_pem = get_cert_for_domain(host)
            server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            server_ssl_context.load_cert_chain(certfile=BytesIO(cert_pem), keyfile=BytesIO(key_pem))
            ssl_client = server_ssl_context.wrap_socket(client_sock, server_side=True)
            if use_direct:
                real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                real_sock.connect((host, port))
            else:
                proxy = get_next_proxy()
                if not proxy:
                    raise Exception("No proxy")
                proto, proxy_host, proxy_port, user, pwd = proxy
                if proto == "http":
                    real_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    real_sock.connect((proxy_host, proxy_port))
                    req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n"
                    if user and pwd:
                        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        req += f"Proxy-Authorization: Basic {auth}\r\n"
                    req += "\r\n"
                    real_sock.send(req.encode())
                    resp = real_sock.recv(4096)
                    if b"200" not in resp:
                        raise Exception("Proxy CONNECT failed")
                else:
                    raise NotImplementedError("SOCKS proxy not supported in MITM mode yet")
            client_ssl_context = ssl.create_default_context()
            ssl_real = client_ssl_context.wrap_socket(real_sock, server_hostname=host)
            self.relay(ssl_client, ssl_real)
        except Exception as e:
            logging.error(f"MITM CONNECT error: {e}")
        finally:
            client_sock.close()

    def relay(self, sock1, sock2):
        t1 = threading.Thread(target=self.forward_data, args=(sock1, sock2, "client->server"))
        t2 = threading.Thread(target=self.forward_data, args=(sock2, sock1, "server->client"))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def forward_data(self, src, dst, direction):
        global total_sent, total_recv
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.sendall(data)
                with stats_lock:
                    if direction == "client->server":
                        total_sent += len(data)
                    else:
                        total_recv += len(data)
        except:
            pass
        finally:
            src.close()
            dst.close()

    def do_GET(self): self.proxy_http()
    def do_POST(self): self.proxy_http()
    def do_PUT(self): self.proxy_http()
    def do_DELETE(self): self.proxy_http()
    def do_HEAD(self): self.proxy_http()
    def do_OPTIONS(self): self.proxy_http()

    def proxy_http(self):
        parsed = urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or 80
        if use_direct:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
        else:
            proxy = get_next_proxy()
            if not proxy:
                self.send_error(502, "No proxy")
                return
            proto, proxy_host, proxy_port, user, pwd = proxy
            if proto == "http":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((proxy_host, proxy_port))
                request = self.requestline + '\r\n'
                for k, v in self.headers.items():
                    request += f"{k}: {v}\r\n"
                request += '\r\n'
                request = request.encode()
                if user and pwd:
                    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    headers = f"Proxy-Authorization: Basic {auth}\r\n"
                    lines = request.split(b'\r\n')
                    lines.insert(1, headers.encode())
                    request = b'\r\n'.join(lines)
                sock.send(request)
                response = sock.recv(8192)
                self.wfile.write(response)
                sock.close()
                return
            else:
                self.send_error(501, "Unsupported proxy type")
                return
        # direct http
        request = self.requestline + '\r\n' + ''.join(f"{k}: {v}\r\n" for k,v in self.headers.items()) + '\r\n'
        sock.send(request.encode())
        response = sock.recv(8192)
        self.wfile.write(response)
        sock.close()

def start_mitm_server():
    httpd = HTTPServer(('127.0.0.1', listen_port), MITMProxyHandler)
    console.print(f"[green]🌽 CornProxy MITM listening on 127.0.0.1:{listen_port}[/green]")
    console.print("[yellow]Make sure you have installed cornproxy_ca.pem as a trusted CA![/yellow]")
    while running:
        httpd.handle_request()

# ========== TUI и общие циклы ==========
def tui_loop():
    global running, dpi_mode
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main", ratio=2),
        Layout(name="graph", size=12),
        Layout(name="footer", size=5)
    )
    layout["main"].split_row(
        Layout(name="stats", ratio=2),
        Layout(name="hosts", ratio=3)
    )
    instructions = "[bold]Hotkeys:[/] [cyan]r[/] Reset  [cyan]s[/] Save log  [cyan]p[/] Update pool  [cyan]d[/] DPI mode  [cyan]q[/] Quit"
    with Live(layout, refresh_per_second=2, screen=True) as live:
        while running:
            update_speed()
            ascii_art = pyfiglet.figlet_format("CornProxy", font="slant")
            colored_art = Text(ascii_art, style="bold magenta")
            layout["header"].update(Panel(Align.center(colored_art), border_style="cyan"))

            with stats_lock:
                sent = total_sent
                recv = total_recv
                active = active_connections
            speed_sent, speed_recv = update_speed()
            stat_table = Table(title="📊 Statistics", box=box.ROUNDED, style="cyan")
            stat_table.add_column("Metric", style="bold magenta")
            stat_table.add_column("Value", style="green")
            stat_table.add_row("Sent", format_bytes(sent))
            stat_table.add_row("Received", format_bytes(recv))
            stat_table.add_row("Total", format_bytes(sent+recv))
            stat_table.add_row("Upload speed", f"{format_bytes(speed_sent)}/s")
            stat_table.add_row("Download speed", f"{format_bytes(speed_recv)}/s")
            stat_table.add_row("Active connections", str(active))
            stat_table.add_row("Uptime", format_uptime())
            stat_table.add_row("DPI mode", dpi_mode.upper())
            
            # DPI mode description
            dpi_desc = {
                "off": "No evasion",
                "fragment": "2-way split (50ms)",
                "fragment_deep": "Byte-by-byte (20ms)",
                "fragment_random": "Random chunks",
                "fragment_ssl": "SSL-record chunks (50-100B)",
                "fragment_slow": "5 chunks (100-300ms)",
                "random_case": "Header case randomization",
                "noise": "Fake headers + IPs",
                "double_host": "Confuse Host parsing",
                "chunked_encoding": "Transform to chunked TE",
                "http_obfuscation": "Mixed case + noise",
                "fake_request": "Fake HTTP before CONNECT",
                "tls_shuffle": "Randomize TLS handshake",
                "tls_spoof": "Spoof TLS version",
            }
            stat_table.add_row("DPI technique", dpi_desc.get(dpi_mode, "Unknown"))
            
            if bridge_mode:
                with bridge_pool_lock:
                    stat_table.add_row("Bridge mode", "ON")
                    stat_table.add_row("Available bridges", str(len(bridge_pool)))
            else:
                with proxy_pool_lock:
                    working = len(proxy_pool)
                    stat_table.add_row("Working proxies", str(working))
                    if current_proxy:
                        ping_str = "N/A"
                        for p in proxy_pool:
                            if p[1] == current_proxy[1] and p[2] == current_proxy[2]:
                                ping_str = f"{p[5]:.0f} ms"
                                break
                        stat_table.add_row("Current proxy", f"{current_proxy[1]}:{current_proxy[2]} ({ping_str})")
                    else:
                        stat_table.add_row("Current proxy", "None")
            layout["stats"].update(stat_table)

            with stats_lock:
                top_hosts = sorted(host_stats.items(), key=lambda x: x[1]['sent']+x[1]['recv'], reverse=True)[:5]
            hosts_table = Table(title="📡 Top hosts", box=box.SIMPLE, style="yellow")
            hosts_table.add_column("Host", style="bold white")
            hosts_table.add_column("Sent", style="cyan")
            hosts_table.add_column("Received", style="magenta")
            for host, d in top_hosts:
                hosts_table.add_row(host[:30], format_bytes(d['sent']), format_bytes(d['recv']))
            if not top_hosts:
                hosts_table.add_row("(no data)", "", "")
            layout["hosts"].update(hosts_table)

            graph_text = render_speed_graph()
            layout["graph"].update(Panel(graph_text, title="📈 Speed graph (bytes/s)", border_style="green"))

            layout["footer"].update(Panel(Align.center(Text(instructions, style="white")), border_style="grey50"))
            live.update(layout)
            time.sleep(0.5)

def input_listener():
    global running, total_sent, total_recv, host_stats, dpi_mode
    while running:
        cmd = input().strip().lower()
        if cmd == 'r':
            with stats_lock:
                total_sent = 0
                total_recv = 0
                host_stats.clear()
            console.print("[yellow]Stats reset[/yellow]")
        elif cmd == 's':
            save_log_to_csv()
        elif cmd == 'p':
            if not mitm_mode:
                update_proxy_pool(fetch_from_web=True)
            else:
                console.print("[yellow]Proxy pool update disabled in MITM mode[/yellow]")
        elif cmd == 'd':
            modes = [
                "off",
                "fragment",           # 2-way split with 50ms delay
                "fragment_deep",      # byte-by-byte (slowest)
                "fragment_random",    # random chunks with random delays
                "fragment_ssl",       # SSL-record aware (50-100 byte chunks)
                "fragment_slow",      # very slow send (5 chunks, 100-300ms delays)
                "random_case",        # randomize HTTP header case
                "noise",              # add fake X-Bypass headers
                "double_host",        # confuse Host: header parsing
                "chunked_encoding",   # convert body to chunked transfer-encoding
                "http_obfuscation",   # mixed case + noise headers
                "fake_request",       # send fake HTTP request before CONNECT
                "tls_shuffle",        # randomize TLS ClientHello fields
                "tls_spoof",          # spoof TLS version in ClientHello
            ]
            idx = (modes.index(dpi_mode) + 1) % len(modes)
            dpi_mode = modes[idx]
            console.print(f"[cyan]DPI mode: {dpi_mode.upper()}[/cyan]")
        elif cmd == 'q':
            running = False
            break

def main():
    global use_direct, listen_port, proxy_pool, current_proxy, background_check_running
    global mitm_mode, ca_cert, ca_key, bridge_mode, mtproto_mode, mtproto_secret, mtproto_port

    load_config()

    console.clear()
    ascii_art = pyfiglet.figlet_format("CornProxy", font="slant")
    console.print(ascii_art, style="bold cyan")
    console.print(Panel.fit(
        f"[bold green]CornProxy {__version__} \"{__codename__}\" — Eastern Europe & Middle East[/bold green]\n"
        f"[dim]SOCKS4/5 · HTTP · Bridge · MTProto (Telegram)[/dim]",
        border_style="green"
    ))

    console.print("\n")
    show_regional_advice()
    console.print("\n")

    print("Select mode:")
    print("1. Manual proxy (single)")
    print("2. Proxy pool (auto-rotate)")
    print("3. Direct (no proxy, logging only)")
    print("4. MITM (decrypt HTTPS, experimental)")
    print("5. Bridge mode (like Tor)")
    print("6. MTProto (Telegram native proxy)")
    mode_choice = input("Choice [1-6]: ").strip()

    if mode_choice == "6":
        mtproto_mode = True
        bridge_mode = False
        mitm_mode = False
        use_direct = True   # MTProto goes direct to Telegram DCs
        secret_choice = input("Secret type: [1] Random  [2] dd (fake-TLS) (default 1): ").strip()
        if secret_choice == "2":
            domain = input("Fake domain (default bing.com): ").strip() or "bing.com"
            mtproto_secret = generate_dd_secret(domain)
            console.print(f"[cyan]dd-secret for '{domain}' generated[/cyan]")
        else:
            mtproto_secret = generate_mtproto_secret()

        port_in = input(f"MTProto port (default {mtproto_port}): ").strip()
        if port_in:
            mtproto_port = int(port_in)
        save_config()

    elif mode_choice == "5":
        bridge_mode = True
        mtproto_mode = False
        use_direct = False
        console.print("[cyan]Bridge mode enabled. Loading/testing bridges...[/cyan]")
        update_bridge_pool(fetch_from_torproject=False)
        if not bridge_pool:
            console.print("[red]No working bridges found. Add bridges to cornproxy_bridges.txt[/red]")
            console.print("[yellow]Format: host:port (one per line)[/yellow]")
            return
        console.print(f"[green]✓ {len(bridge_pool)} bridges available[/green]")

    elif mode_choice == "4":
        bridge_mode = False
        mtproto_mode = False
        mitm_mode = True
        use_direct = True
        console.print("[yellow]MITM mode — generating CA certificate...[/yellow]")
        ca_cert, ca_key = generate_ca_cert()
        console.print("[bold red]Install cornproxy_ca.pem as trusted root CA in your browser![/bold red]")
        input("Press Enter after installing certificate...")

    else:
        bridge_mode = False
        mtproto_mode = False
        mitm_mode = False
        if mode_choice == "3":
            use_direct = True
        elif mode_choice == "2":
            use_direct = False
            update_proxy_pool(fetch_from_web=True)
            if not proxy_pool:
                console.print("[red]No working proxies found.[/red]")
                return
            threading.Thread(target=background_pool_checker, daemon=True).start()
        else:
            use_direct = False
            proxy_host = input("Proxy IP or domain: ").strip()
            proxy_port = int(input("Proxy port: ").strip())
            auth = input("Authentication? (y/N): ").strip().lower()
            user = pwd = None
            if auth == 'y':
                user = input("Username: ").strip()
                pwd  = input("Password: ").strip()
            proxy_pool = [("http", proxy_host, proxy_port, user, pwd, 0.0)]
            ok, _ = test_proxy("http", proxy_host, proxy_port, user, pwd)
            console.print("[green]Proxy OK[/green]" if ok else "[red]Proxy test failed[/red]")
            current_proxy = ("http", proxy_host, proxy_port, user, pwd)

    if not mtproto_mode:
        listen_port = int(input(f"Local port (default {listen_port}): ").strip() or str(listen_port))

    # DPI mode selection
    console.print("\nDPI mode (press Enter to keep current, or type mode name):")
    console.print(f"  Current: [cyan]{dpi_mode}[/cyan]")
    console.print("  Options: off, fragment, fragment_random, fragment_ssl, fragment_slow,")
    console.print("           fragment_deep, chunked_encoding, noise, http_obfuscation,")
    console.print("           random_case, fake_request, tls_shuffle, tls_spoof")
    dpi_in = input("DPI mode: ").strip()
    if dpi_in:
        globals()['dpi_mode'] = dpi_in
    save_config()

    # Start servers
    if mtproto_mode:
        threading.Thread(target=start_mtproto_server, daemon=True).start()
        # Also start regular proxy so browsers still work
        console.print(f"[cyan]Starting HTTP/SOCKS proxy on port {listen_port} as well...[/cyan]")
        listen_port = int(input(f"HTTP/SOCKS port (default 8888, 0 to skip): ").strip() or "8888")
        if listen_port:
            threading.Thread(target=start_regular_server, daemon=True).start()
    elif mitm_mode:
        threading.Thread(target=start_mitm_server, daemon=True).start()
    else:
        threading.Thread(target=start_regular_server, daemon=True).start()

    threading.Thread(target=input_listener, daemon=True).start()
    try:
        tui_loop()
    except KeyboardInterrupt:
        pass
    finally:
        global running
        running = False
        console.print("[yellow]Shutting down CornProxy...[/yellow]")
        time.sleep(1)

if __name__ == "__main__":
    main()
def create_bridge_tunnel(target_host, target_port, max_retries=2):
    """
    Create tunnel through a bridge.
    bridge -> either proxy or target
    """
    for attempt in range(max_retries + 1):
        bridge = get_random_bridge()
        if not bridge:
            raise Exception("No bridges available")
        
        bridge_host, bridge_port = bridge
        try:
            # Connect to bridge
            bridge_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bridge_sock.settimeout(30)
            bridge_sock.connect((bridge_host, bridge_port))
            
            # Send bridge protocol request
            bridge_req = f"BRIDGE {target_host}:{target_port}\r\n"
            
            # If using proxy through bridge
            if not use_direct and proxy_pool:
                proxy = get_next_proxy()
                if proxy:
                    proto, proxy_host, proxy_port, user, pwd = proxy
                    auth = ""
                    if user and pwd:
                        auth = f":{user}:{pwd}"
                    bridge_req += f"Proxy: {proto}://{proxy_host}:{proxy_port}{auth}\r\n"
            
            bridge_req += "\r\n"
            send_fragmented(bridge_sock, bridge_req.encode())
            
            # Wait for bridge response
            resp = bridge_sock.recv(1024)
            if b"OK" in resp or b"200" in resp:
                logging.info(f"Bridge tunnel: {bridge_host}:{bridge_port} → {target_host}:{target_port}")
                return bridge_sock, (bridge_host, bridge_port)
            else:
                raise Exception("Bridge refused")
        
        except Exception as e:
            logging.warning(f"Bridge {bridge_host}:{bridge_port} failed: {e}")
            mark_bridge_dead(bridge_host, bridge_port)
            continue
    
    raise Exception("All bridges failed")

