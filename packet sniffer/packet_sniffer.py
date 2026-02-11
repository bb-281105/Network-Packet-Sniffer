#!/usr/bin/env python3
"""
Universal Packet Sniffer - Works on Windows (NO Npcap), Linux, Mac
Educational Purpose Only
Run as Administrator/root
"""

import argparse
import sys
import socket
import struct
import textwrap
import time
import platform
import os
import signal

# Global variable to control sniffing
stop_sniffing = False

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global stop_sniffing
    print("\n[!] Stopping packet capture...")
    stop_sniffing = True

def ethernet_header(data):
    """Parse Ethernet header (Linux/Mac only)"""
    if platform.system() != "Windows":
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return {
            'dest_mac': ':'.join(format(b, '02x') for b in dest_mac),
            'src_mac': ':'.join(format(b, '02x') for b in src_mac),
            'protocol': socket.htons(proto)
        }
    return None

def ip_header(data):
    """Parse IP header"""
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return {
        'version': version,
        'header_len': header_len,
        'ttl': ttl,
        'protocol': proto,
        'src': socket.inet_ntoa(src),
        'dst': socket.inet_ntoa(target),
        'data': data[header_len:]
    }

def tcp_header(data):
    """Parse TCP header"""
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    
    flags = {
        'urg': (offset_reserved_flags & 32) >> 5,
        'ack': (offset_reserved_flags & 16) >> 4,
        'psh': (offset_reserved_flags & 8) >> 3,
        'rst': (offset_reserved_flags & 4) >> 2,
        'syn': (offset_reserved_flags & 2) >> 1,
        'fin': offset_reserved_flags & 1
    }
    
    return {
        'src_port': src_port,
        'dst_port': dest_port,
        'seq': seq,
        'ack': ack,
        'flags': flags,
        'header_len': offset,
        'data': data[offset:]
    }

def udp_header(data):
    """Parse UDP header"""
    src_port, dest_port, size = struct.unpack('! H H H', data[:6])
    return {
        'src_port': src_port,
        'dst_port': dest_port,
        'size': size,
        'data': data[8:]
    }

def icmp_header(data):
    """Parse ICMP header"""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return {
        'type': icmp_type,
        'code': code,
        'checksum': checksum,
        'data': data[4:]
    }

def format_multi_line(prefix, string, size=80):
    """Format payload for nice printing"""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(b) for b in string[:size])
        if len(string) > size:
            string = string[:size] + '...'
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def print_packet(packet_data, eth_header=None):
    """Display packet information"""
    try:
        # Parse IP header
        ip = ip_header(packet_data)
        protocol = ip['protocol']
        
        # Get protocol name and parse appropriate header
        if protocol == 6:  # TCP
            proto_name = "TCP"
            tcp = tcp_header(ip['data'])
            info = f"Ports: {tcp['src_port']} -> {tcp['dst_port']}"
            
            # Show TCP flags
            flags = ''.join([k.upper() for k, v in tcp['flags'].items() if v])
            if flags:
                info += f" [{flags}]"
                
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            udp = udp_header(ip['data'])
            info = f"Ports: {udp['src_port']} -> {udp['dst_port']}"
            
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            icmp = icmp_header(ip['data'])
            info = f"Type: {icmp['type']} Code: {icmp['code']}"
            
        else:
            proto_name = f"Other({protocol})"
            info = ""
        
        # Print packet info
        timestamp = time.strftime('%H:%M:%S')
        
        # Ethernet info (Linux/Mac only)
        if eth_header:
            print(f"\n[{timestamp}] {proto_name} {eth_header['src_mac']} -> {eth_header['dest_mac']}")
        
        # IP info
        print(f"[{proto_name}] {ip['src']:20} -> {ip['dst']:20} {info}")
        
        # Payload for small packets
        if protocol in [6, 17, 1]:
            payload = ip['data'][ip['header_len']:]
            if len(payload) > 0 and len(payload) < 200:
                print(format_multi_line("    Payload: ", payload[:100]))
        
        print("-" * 70)
        
    except Exception as e:
        print(f"[Error processing packet: {e}]")

def windows_sniffer(count=0, filter_exp=""):
    """Windows-specific raw socket sniffer - NO NPCAP REQUIRED"""
    try:
        # Create raw socket for IP layer
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        # Get IP address of default interface
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        # Bind to the interface
        conn.bind((ip_address, 0))
        
        # Include IP headers
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Enable promiscuous mode
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        print(f"[*] Windows raw socket initialized on {ip_address}")
        print("[!] NOTE: Incoming TCP packets are NOT visible (Windows limitation)")
        print("[!]       UDP, ICMP, and outgoing TCP work normally\n")
        
        packet_count = 0
        
        while not stop_sniffing:
            try:
                # Receive packet
                packet, _ = conn.recvfrom(65565)
                packet_count += 1
                
                # Filter by IP if specified
                if filter_exp:
                    if 'icmp' in filter_exp.lower() and packet[9] != 1:
                        continue
                    if 'udp' in filter_exp.lower() and packet[9] != 17:
                        continue
                    if 'tcp' in filter_exp.lower() and packet[9] != 6:
                        continue
                
                print_packet(packet)
                
                if count > 0 and packet_count >= count:
                    break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Receive error: {e}")
                
    finally:
        # Disable promiscuous mode
        try:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except:
            pass
        conn.close()

def linux_sniffer(interface=None, count=0, filter_exp=""):
    """Linux/Mac sniffer using AF_PACKET (full ethernet frames)"""
    try:
        # Create raw socket for Ethernet frames
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        
        if interface:
            conn.bind((interface, 0))
            print(f"[*] Listening on interface: {interface}")
        else:
            print("[*] Listening on default interface")
        
        packet_count = 0
        
        while not stop_sniffing:
            try:
                # Receive packet
                raw_packet, addr = conn.recvfrom(65535)
                packet_count += 1
                
                # Parse Ethernet header
                eth = ethernet_header(raw_packet)
                
                # Check if it's IP packet (0x0800)
                if eth and eth['protocol'] == 8:
                    ip_packet = raw_packet[14:]
                    
                    # Apply BPF-like filter
                    if filter_exp:
                        proto = ip_packet[9]
                        if 'icmp' in filter_exp.lower() and proto != 1:
                            continue
                        if 'udp' in filter_exp.lower() and proto != 17:
                            continue
                        if 'tcp' in filter_exp.lower() and proto != 6:
                            continue
                    
                    print_packet(ip_packet, eth)
                
                if count > 0 and packet_count >= count:
                    break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Receive error: {e}")
                
    finally:
        conn.close()

def start_sniffing(interface=None, count=0, filter_exp=""):
    """Platform-aware packet sniffer"""
    system = platform.system()
    
    if system == "Windows":
        print("[*] Starting Windows raw socket sniffer...")
        print("[*] Press Ctrl+C to stop\n")
        windows_sniffer(count, filter_exp)
        
    else:  # Linux/Mac
        print("[*] Starting Linux/Mac packet sniffer...")
        print("[*] Press Ctrl+C to stop\n")
        linux_sniffer(interface, count, filter_exp)

def list_interfaces_windows():
    """List Windows interfaces"""
    print("[*] Available network interfaces:")
    print("-" * 50)
    
    try:
        import subprocess
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        adapters = []
        for line in lines:
            if 'adapter' in line.lower() and ':' in line:
                adapter = line.strip().replace(':', '').replace('adapter', '').strip()
                adapters.append(adapter)
                print(f"  • {adapter}")
        
        print("\n[*] Get your IP address:")
        print("    Run: ipconfig | findstr IPv4")
        print("\n[*] Use this script WITHOUT interface parameter on Windows")
        print("    The script auto-detects your IP address")
        
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Universal Packet Sniffer - Works on Windows (NO Npcap), Linux, Mac",
        epilog="""
Examples:
  Windows (NO NPCAP): python packet_sniffer.py -f udp
  Windows:           python packet_sniffer.py -c 50 -f icmp
  Linux/Mac:         sudo python3 packet_sniffer.py -i eth0 -f tcp port 80
  Linux/Mac:         sudo python3 packet_sniffer.py -l
        """
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface (Linux/Mac only. Windows auto-detects)"
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)"
    )
    
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="Filter (udp, tcp, icmp) - Windows only supports these three"
    )
    
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List available network interfaces"
    )
    
    args = parser.parse_args()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    system = platform.system()
    
    # Check privileges
    if system == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] ERROR: Must run as Administrator!")
                print("[!] Right-click Command Prompt → 'Run as Administrator'")
                sys.exit(1)
        except:
            print("[!] WARNING: Could not verify admin privileges")
    else:  # Linux/Mac
        if os.geteuid() != 0:
            print("[!] ERROR: Must run as root!")
            print("[!] Use: sudo python3 packet_sniffer.py")
            sys.exit(1)
    
    if args.list:
        if system == "Windows":
            list_interfaces_windows()
        else:
            try:
                interfaces = os.listdir('/sys/class/net/')
                print("[*] Available interfaces:")
                for iface in interfaces:
                    print(f"  • {iface}")
            except:
                print("[*] Run: ip link show")
        return
    
    print("\n" + "=" * 70)
    print("  UNIVERSAL PACKET SNIFFER - EDUCATIONAL USE ONLY")
    print("=" * 70)
    print(f"[*] System: {system}")
    
    if args.filter:
        print(f"[*] Filter: {args.filter}")
    if args.count > 0:
        print(f"[*] Packet limit: {args.count}")
    
    print("=" * 70 + "\n")
    
    start_sniffing(args.interface, args.count, args.filter)

if __name__ == "__main__":
    main()
