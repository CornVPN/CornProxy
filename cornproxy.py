import socket
import sys
import threading
import time
import csv
import random
import base64
import os
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

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
    init(autoreset=True)
except ImportError as e:
    print(f"Missing library: {e}. Install: pip install rich pysocks plotext pyfiglet colorama requests beautifulsoup4 lxml")
    sys.exit(1)

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
dpi_mode = "off"

speed_history = []
last_update = time.time()
prev_sent = 0
prev_recv = 0
start_time = time.time()

console = Console()

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
    console.print(f"[green]Found {len(proxies)} free proxies[/green]")
    return proxies

def test_proxy(proto, ip, port, user, password):
    target_host = "httpbin.org"
    target_port = 80
    try:
        if proto == "http":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
            if user and password:
                auth = base64.b64encode(f"{user}:{password}".encode()).decode()
                req += f"Proxy-Authorization: Basic {auth}\r\n"
            req += "\r\n"
            sock.send(req.encode())
            resp = sock.recv(1024)
            sock.close()
            return b"200" in resp
        elif proto in ("socks5", "socks4"):
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                           ip, port, username=user, password=password)
            sock.settimeout(5)
            sock.connect((target_host, target_port))
            sock.close()
            return True
    except:
        return False
    return False

def update_proxy_pool(fetch_from_web=True):
    global proxy_pool
    proxies = load_proxy_list_from_file()
    if fetch_from_web:
        proxies.extend(fetch_free_proxies())
    console.print("[cyan]Testing proxies (may take a while)...[/cyan]")
    good = []
    for p in proxies:
        if test_proxy(*p):
            good.append(p)
    with proxy_pool_lock:
        proxy_pool = good
    console.print(f"[green]Proxy pool updated: {len(proxy_pool)} working proxies[/green]")

def get_next_proxy():
    with proxy_pool_lock:
        if not proxy_pool:
            return None
        global proxy_pool_index
        idx = proxy_pool_index % len(proxy_pool)
        proxy_pool_index += 1
        return proxy_pool[idx]

def mark_proxy_dead(proxy):
    with proxy_pool_lock:
        if proxy in proxy_pool:
            proxy_pool.remove(proxy)
            console.print(f"[yellow]Proxy {proxy[1]}:{proxy[2]} removed from pool[/yellow]")

def dpi_obfuscate_http_request(request_data):
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
    except:
        pass
    return request_data

def send_fragmented(sock, data):
    if dpi_mode != "fragment" or len(data) < 2:
        sock.sendall(data)
        return
    sock.sendall(data[:1])
    time.sleep(0.05)
    sock.sendall(data[1:])

def connect_http_proxy(proxy_host, proxy_port, target_host, target_port, user=None, password=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((proxy_host, proxy_port))
    req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}\r\n"
    if user and password:
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    req += "\r\n"
    sock.send(req.encode())
    resp = sock.recv(4096)
    if b"200" not in resp:
        raise Exception("HTTP proxy CONNECT failed")
    return sock

def send_http_via_proxy(proxy_host, proxy_port, request, user=None, password=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))
    if user and password:
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = f"Proxy-Authorization: Basic {auth}\r\n"
        lines = request.split(b'\r\n')
        lines.insert(1, headers.encode())
        request = b'\r\n'.join(lines)
    sock.send(request)
    return sock

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
    except:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass

def handle_client(client_sock):
    global active_connections
    with stats_lock:
        active_connections += 1
    try:
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
            proxy = get_next_proxy()
            if not proxy:
                raise Exception("No proxy available")
            proto, proxy_host, proxy_port, user, pwd = proxy

            if proto == "http":
                if method.upper() == 'CONNECT':
                    target_sock = connect_http_proxy(proxy_host, proxy_port, target_host, target_port, user, pwd)
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
                    target_sock = send_http_via_proxy(proxy_host, proxy_port, request, user, pwd)
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
            elif proto in ("socks5", "socks4"):
                if method.upper() == 'CONNECT':
                    target_sock = socks.socksocket()
                    target_sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                                          proxy_host, proxy_port, username=user, password=pwd)
                    target_sock.connect((target_host, target_port))
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
                    target_sock = socks.socksocket()
                    target_sock.set_proxy(socks.SOCKS5 if proto == "socks5" else socks.SOCKS4,
                                          proxy_host, proxy_port, username=user, password=pwd)
                    target_sock.connect((target_host, target_port))
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

    except Exception:
        pass
    finally:
        with stats_lock:
            active_connections -= 1
        try:
            client_sock.close()
        except:
            pass

def start_proxy_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', listen_port))
    server.listen(50)
    console.print(f"[green]🌽 CornProxy listening on 127.0.0.1:{listen_port}[/green]")
    while running:
        try:
            client_sock, addr = server.accept()
            client_sock.settimeout(30)
            t = threading.Thread(target=handle_client, args=(client_sock,))
            t.daemon = True
            t.start()
        except:
            pass
    server.close()

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
    instructions = "[bold]Hotkeys:[/] [cyan]r[/] Reset stats  [cyan]s[/] Save log  [cyan]p[/] Update proxy pool  [cyan]d[/] DPI mode cycle  [cyan]q[/] Quit"
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
            with proxy_pool_lock:
                stat_table.add_row("Working proxies", str(len(proxy_pool)))
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
            update_proxy_pool(fetch_from_web=True)
        elif cmd == 'd':
            modes = ["off", "fragment", "random_case", "noise"]
            idx = (modes.index(dpi_mode) + 1) % len(modes)
            dpi_mode = modes[idx]
            console.print(f"[cyan]DPI mode changed to {dpi_mode.upper()}[/cyan]")
        elif cmd == 'q':
            running = False
            break

def main():
    global use_direct, listen_port, proxy_pool
    console.clear()
    ascii_art = pyfiglet.figlet_format("CornProxy", font="slant")
    console.print(ascii_art, style="bold cyan")
    console.print(Panel.fit("[bold green]Welcome! Proxy logger with CONNECT fixed[/bold green]", border_style="green"))

    print("\nSelect mode:")
    print("1. Manual proxy (single)")
    print("2. Proxy pool (auto-rotate, fetches free proxies)")
    print("3. Direct (no proxy, logging only)")
    mode_choice = input("Choice [1/2/3]: ").strip()

    if mode_choice == "3":
        use_direct = True
    elif mode_choice == "2":
        use_direct = False
        update_proxy_pool(fetch_from_web=True)
        if not proxy_pool:
            console.print("[red]No working proxies found. Exiting.[/red]")
            return
    else:
        use_direct = False
        proxy_host = input("Proxy IP or domain: ").strip()
        proxy_port = int(input("Proxy port: ").strip())
        auth = input("Authentication? (y/N): ").strip().lower()
        user = pwd = None
        if auth == 'y':
            user = input("Username: ").strip()
            pwd = input("Password: ").strip()
        proxy_pool = [("http", proxy_host, proxy_port, user, pwd)]
        if not test_proxy("http", proxy_host, proxy_port, user, pwd):
            console.print("[red]Proxy test failed. It might not work.[/red]")
        else:
            console.print("[green]Proxy works.[/green]")

    listen_port = int(input("Local port (default 8888): ").strip() or "8888")

    threading.Thread(target=input_listener, daemon=True).start()
    threading.Thread(target=start_proxy_server, daemon=True).start()
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