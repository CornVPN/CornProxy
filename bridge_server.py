#!/usr/bin/env python3
"""
CornProxy Bridge Server
========================

Simple standalone bridge server that accepts bridge protocol connections
and forwards them to a real proxy or target.

This makes your CornProxy invisible by hiding it behind this bridge.

Usage:
    python3 bridge_server.py 9999 real-proxy.example.com 8080

Then add to cornproxy_bridges.txt:
    your-bridge-server-ip:9999
"""

import socket
import threading
import time
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

class BridgeServer:
    def __init__(self, listen_port, forward_host, forward_port):
        self.listen_port = listen_port
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.active_connections = 0
        self.total_bytes = 0
        self.lock = threading.Lock()
        logging.info(f"Bridge configured: 0.0.0.0:{listen_port} -> {forward_host}:{forward_port}")
    
    def handle_client(self, client_sock, client_addr):
        """Handle incoming bridge client connection."""
        with self.lock:
            self.active_connections += 1
            active = self.active_connections
        
        logging.info(f"[{active}] Client connected from {client_addr}")
        
        try:
            # Read bridge protocol request
            request = b''
            while len(request) < 4096:
                chunk = client_sock.recv(4096)
                if not chunk:
                    logging.warning(f"[{active}] Client disconnected before sending request")
                    return
                request += chunk
                if b'\r\n\r\n' in request:
                    break
            
            # Parse request (format: "BRIDGE target_host:target_port\r\n...")
            lines = request.split(b'\r\n')
            cmd_line = lines[0].decode('utf-8', errors='ignore').strip()
            
            logging.debug(f"[{active}] Request: {cmd_line}")
            
            # Check if it's a valid bridge request
            if not cmd_line.startswith('BRIDGE'):
                # Fall back to direct CONNECT or accept anyway
                logging.debug(f"[{active}] Non-BRIDGE request, assuming proxy protocol")
            
            # Connect to forward target (real proxy or endpoint)
            logging.debug(f"[{active}] Connecting to {self.forward_host}:{self.forward_port}")
            forward_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            forward_sock.settimeout(30)
            
            try:
                forward_sock.connect((self.forward_host, self.forward_port))
            except Exception as e:
                logging.error(f"[{active}] Failed to connect to {self.forward_host}:{self.forward_port}: {e}")
                client_sock.send(b"ERROR: Cannot connect to proxy\r\n")
                return
            
            # Send OK response to client
            client_sock.send(b"OK: Connected\r\n")
            logging.info(f"[{active}] Bridge tunnel established")
            
            # Start relay threads
            t1 = threading.Thread(target=self.relay, args=(client_sock, forward_sock, active, 'C->P'))
            t2 = threading.Thread(target=self.relay, args=(forward_sock, client_sock, active, 'P->C'))
            t1.daemon = True
            t2.daemon = True
            t1.start()
            t2.start()
            
            # Wait for both threads to finish
            t1.join()
            t2.join()
            
            logging.info(f"[{active}] Client disconnected")
        
        except Exception as e:
            logging.error(f"[{active}] Error: {e}")
        
        finally:
            try:
                client_sock.close()
            except:
                pass
            with self.lock:
                self.active_connections -= 1
    
    def relay(self, src, dst, conn_id, direction):
        """Relay data between two sockets."""
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    logging.debug(f"[{conn_id}] {direction}: EOF")
                    break
                dst.sendall(data)
                with self.lock:
                    self.total_bytes += len(data)
        except Exception as e:
            logging.debug(f"[{conn_id}] {direction}: {e}")
        finally:
            try:
                src.close()
            except:
                pass
            try:
                dst.close()
            except:
                pass
    
    def print_stats(self):
        """Print connection statistics periodically."""
        while True:
            time.sleep(30)
            with self.lock:
                mb = self.total_bytes / (1024 * 1024)
                logging.info(f"Stats: {self.active_connections} active connections, {mb:.1f} MB relayed")
    
    def run(self):
        """Start the bridge server."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('0.0.0.0', self.listen_port))
        server_sock.listen(50)
        
        logging.info(f"Bridge server listening on 0.0.0.0:{self.listen_port}")
        logging.info(f"Forwarding to {self.forward_host}:{self.forward_port}")
        logging.info("Waiting for connections...")
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.print_stats, daemon=True)
        stats_thread.start()
        
        try:
            while True:
                try:
                    client_sock, client_addr = server_sock.accept()
                    client_sock.settimeout(30)
                    t = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    t.start()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logging.error(f"Accept error: {e}")
        except KeyboardInterrupt:
            logging.info("\nShutting down bridge server...")
        finally:
            server_sock.close()
            logging.info("Bridge server stopped")


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 bridge_server.py <listen_port> <forward_host> <forward_port>")
        print()
        print("Examples:")
        print("  # Bridge to local proxy on port 8080")
        print("  python3 bridge_server.py 9999 localhost 8080")
        print()
        print("  # Bridge to remote proxy")
        print("  python3 bridge_server.py 9999 proxy.example.com 8080")
        print()
        print("Then add to cornproxy_bridges.txt:")
        print("  your.server.ip:9999")
        sys.exit(1)
    
    try:
        listen_port = int(sys.argv[1])
        forward_host = sys.argv[2]
        forward_port = int(sys.argv[3])
    except ValueError:
        print("Error: ports must be numeric")
        sys.exit(1)
    
    bridge = BridgeServer(listen_port, forward_host, forward_port)
    bridge.run()


if __name__ == '__main__':
    main()
