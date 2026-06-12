# network_utils.py
import socket
import struct
import threading
import logging
from typing import Tuple, Optional

class DNSTunnel:
    def __init__(self, listen_port: int = 5353, upstream: Tuple[str, int] = ("1.1.1.1", 853)):
        self.listen_port = listen_port
        self.upstream = upstream
        self.sock: Optional[socket.socket] = None
        self.running = False
        
    def start(self):
        self.running = True
        self.sock = create_dual_stack_socket(socket.SOCK_DGRAM)
        self.sock.bind(("::", self.listen_port))
        
        print(f"[+] DNS Tunnel active on UDP :{self.listen_port} → TCP {self.upstream[0]}:{self.upstream[1]}")
        threading.Thread(target=self._listen_loop, daemon=True).start()
        
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
            
    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                threading.Thread(
                    target=self._forward_tcp, 
                    args=(data, addr), 
                    daemon=True
                ).start()
            except OSError:
                if not self.running: break
            except Exception as e:
                logging.debug(f"DNS Tunnel recv error: {e}")
                
    def _forward_tcp(self, query: bytes, client_addr: tuple):
        tcp_sock = None
        try:
            tcp_query = struct.pack(">H", len(query)) + query
            
            tcp_sock = socket.create_connection(self.upstream, timeout=5)
            tcp_sock.sendall(tcp_query)
            
            
            length_data = tcp_sock.recv(2)
            if len(length_data) < 2: return
            resp_length = struct.unpack(">H", length_data)[0]
            
            
            response = b""
            while len(response) < resp_length:
                chunk = tcp_sock.recv(resp_length - len(response))
                if not chunk: break
                response += chunk
            self.sock.sendto(response, client_addr)
            
        except Exception as e:
            logging.debug(f"DNS TCP forward failed for {client_addr}: {e}")
        finally:
            if tcp_sock:
                tcp_sock.close()


def create_dual_stack_socket(sock_type: int = socket.SOCK_STREAM) -> socket.socket:
    """
    Создает IPv6 сокет с поддержкой Dual-Stack (принимает и IPv4, и IPv6).
    Автоматически настраивает SO_REUSEADDR.
    """
    sock = socket.socket(socket.AF_INET6, sock_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except (AttributeError, OSError):
        logging.warning("IPV6_V6ONLY not supported, IPv4-mapped connections may fail")
        
    return sock
