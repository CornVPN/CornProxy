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
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

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
    init(autoreset=True)
except ImportError as e:
    print(f"Missing library: {e}. Install: pip install rich pysocks plotext pyfiglet colorama requests beautifulsoup4 lxml cryptography")
    sys.exit(1)


total_sent = 0
total_recv = 0
active_connections = 0
host_stats = defaultdict(lambda: {'sent': 0, 'recv': 0})
stats_lock = threading.Lock()
running = True
listen_port = 8888
use_direct = False
proxy_pool = []          # (proto, host, port, user, pass, ping_ms)
proxy_pool_lock = threading.Lock()
proxy_pool_index = 0
current_proxy = None
dpi_mode = "off"
mitm_mode = False
ca_cert = None
ca_key = None
cert_cache = {}
background_check_running = False

speed_history = []
last_update = time.time()
prev_sent = 0
prev_recv = 0
start_time = time.time()

console = Console()

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

def load_proxy_list_from_file(filename="proxies.txt"):
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

# ========== Anti-DPI ==========

def dpi_obfuscate_http_request(request_data):
    """Apply HTTP-level DPI evasion techniques."""
    if dpi_mode == "off":
        return request_data
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
    """TCP-level fragmentation with various DPI evasion patterns."""
    if dpi_mode == "off":
        sock.sendall(data)
    
    elif dpi_mode == "fragment":
        # Simple 2-way split with delay
        if len(data) >= 2:
            sock.sendall(data[:1])
            time.sleep(0.05)
            sock.sendall(data[1:])
        else:
            sock.sendall(data)
    
    elif dpi_mode == "fragment_deep":
        # Byte-by-byte with micro-delays (heavy but effective)
        for i in range(len(data)):
            sock.sendall(data[i:i+1])
            time.sleep(0.02)
    
    elif dpi_mode == "fragment_random":
        # Random fragmentation pattern
        if len(data) <= 1:
            sock.sendall(data)
            return
        chunks = []
        pos = 0
        while pos < len(data):
            chunk_size = random.randint(1, max(2, len(data) - pos) // 2)
            chunks.append(data[pos:pos+chunk_size])
            pos += chunk_size
        for chunk in chunks:
            sock.sendall(chunk)
            time.sleep(random.uniform(0.01, 0.05))
    
    elif dpi_mode == "fragment_ssl":
        # SSL/TLS aware fragmentation (small TLS record size)
        if len(data) < 20:
            sock.sendall(data)
        else:
            # TLS record layer: split into ~50-100 byte chunks
            for i in range(0, len(data), random.randint(50, 100)):
                chunk = data[i:i+random.randint(50, 100)]
                sock.sendall(chunk)
                time.sleep(0.02)
    
    elif dpi_mode == "fragment_slow":
        # Very slow send with random delays (firewall timeout bypass)
        chunk_size = max(1, len(data) // 5)
        for i in range(0, len(data), chunk_size):
            sock.sendall(data[i:i+chunk_size])
            time.sleep(random.uniform(0.1, 0.3))
    
    else:
        sock.sendall(data)


def patch_tls_clienthello(data):
    """Modify TLS ClientHello to evade DPI fingerprinting."""
    if dpi_mode not in ("tls_shuffle", "tls_spoof"):
        return data
    
    try:
        # Very basic ClientHello detection - check for TLS record
        if len(data) < 43 or data[0] != 0x16:  # 0x16 = Handshake
            return data
        
        # Extract handshake type (should be 0x01 for ClientHello)
        if data[5] != 0x01:
            return data
        
        # Randomize TLS version bytes to confuse detection
        # Standard: data[9:11] = TLS version
        if len(data) > 11:
            # Change reported version (still uses downgrade safi for real connection)
            data = bytearray(data)
            data[9] = 0x03
            data[10] = random.choice([0x01, 0x02, 0x03])  # TLS 1.0/1.1/1.2
            return bytes(data)
    except:
        pass
    return data

def send_fake_http_request_before_connect(sock, proxy_host):
    """Send fake HTTP request to warm up connection and confuse DPI."""
    if dpi_mode != "fake_request":
        return
    fake_req = f"GET /{random.randint(1000,9999)}.html HTTP/1.1\r\nHost: {proxy_host}\r\nConnection: close\r\n\r\n"
    sock.send(fake_req.encode())
    time.sleep(0.1)
    try:
        sock.recv(4096)
    except:
        pass

def apply_dpi_evasion_on_connect(sock, target_host, target_port, proxy_host, user=None, pwd=None):
    """Build CONNECT request with applied DPI evasion techniques."""
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
    if user and pwd:
        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    
    # Add evasion headers based on mode
    if dpi_mode == "noise":
        req += f"X-Forwarded-For: {random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}\r\n"
        req += f"X-Real-IP: 127.0.0.1\r\n"
    elif dpi_mode in ("http_obfuscation", "random_case"):
        req += f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    
    req += "\r\n"
    return req.encode()

def combine_dpi_modes():
    """Get list of DPI techniques to apply in sequence (for experimental 'combo' mode)."""
    available = []
    if dpi_mode in ("fragment", "fragment_deep", "fragment_random", "fragment_ssl", "fragment_slow"):
        available.append('fragment')
    if dpi_mode in ("random_case", "noise", "double_host", "chunked_encoding", "http_obfuscation"):
        available.append('http')
    if dpi_mode in ("tls_shuffle", "tls_spoof"):
        available.append('tls')
    return available


def forward(src, dst, direction, host=None):
    global total_sent, total_recv, host_stats
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
            with stats_lock:
                if direction == 'sent':
                    total_sent += len(data)
                    if host:
                        host_stats[host]['sent'] += len(data)
                else:
                    total_recv += len(data)
                    if host:
                        host_stats[host]['recv'] += len(data)
    except Exception as e:
        logging.debug(f"Forward error: {e}")
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass

def create_tunnel_with_retry(target_host, target_port, max_retries=2):
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
    global use_direct, listen_port, proxy_pool, current_proxy, background_check_running, mitm_mode, ca_cert, ca_key
    console.clear()
    ascii_art = pyfiglet.figlet_format("CornProxy", font="slant")
    console.print(ascii_art, style="bold cyan")
    console.print(Panel.fit("[bold green]CornProxy v4.1 - MITM + Advanced Anti-DPI + SOCKS[/bold green]", border_style="green"))

    print("\n[Available DPI Evasion Modes]")
    print("  fragment          - Split into 2 packets (50ms delay)")
    print("  fragment_deep     - Byte-by-byte (slowest, most evasive)")
    print("  fragment_random   - Random chunk sizes with random delays")
    print("  fragment_ssl      - SSL-aware fragmentation (50-100B chunks)")
    print("  fragment_slow     - Very slow delivery (100-300ms between chunks)")
    print("  random_case       - HTTP header case randomization")
    print("  noise             - Add fake X-Bypass headers & spoofed IPs")
    print("  double_host       - Confuse Host: header parsing")
    print("  chunked_encoding  - Transform HTTP body to chunked transfer-encoding")
    print("  http_obfuscation  - Mixed case randomization + noise")
    print("  fake_request      - Send fake HTTP GET before CONNECT")
    print("  tls_shuffle       - Randomize TLS ClientHello order")
    print("  tls_spoof         - Spoof TLS version in handshake")
    print("  off               - No DPI evasion (default)\n")

    print("Select mode:")
    print("1. Manual proxy (single)")
    print("2. Proxy pool (auto-rotate, fetches free proxies)")
    print("3. Direct (no proxy, logging only)")
    print("4. MITM mode (decrypt HTTPS) - EXPERIMENTAL, for direct connections only")
    mode_choice = input("Choice [1/2/3/4]: ").strip()

    if mode_choice == "4":
        mitm_mode = True
        use_direct = True
        console.print("[yellow]MITM mode enabled. Generating/loading CA certificate...[/yellow]")
        ca_cert, ca_key = generate_ca_cert()
        console.print("[bold red]IMPORTANT: Install cornproxy_ca.pem as a trusted root CA in your browser/system![/bold red]")
        console.print("[cyan]Press Enter to continue after installing certificate...[/cyan]")
        input()
    else:
        mitm_mode = False
        if mode_choice == "3":
            use_direct = True
        elif mode_choice == "2":
            use_direct = False
            update_proxy_pool(fetch_from_web=True)
            if not proxy_pool:
                console.print("[red]No working proxies found. Exiting.[/red]")
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
                pwd = input("Password: ").strip()
            proxy_pool = [("http", proxy_host, proxy_port, user, pwd, 0.0)]
            if not test_proxy("http", proxy_host, proxy_port, user, pwd)[0]:
                console.print("[red]Proxy test failed. It might not work.[/red]")
            else:
                console.print("[green]Proxy works.[/green]")
            current_proxy = ("http", proxy_host, proxy_port, user, pwd)

    listen_port = int(input("Local port (default 8888): ").strip() or "8888")

    if mitm_mode:
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