#!/usr/bin/env python3
"""
Simple Network Packet Sniffer
Educational Purpose Only
Requires root/admin privileges
"""

import argparse
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import sys
import signal

# Global variable to control sniffing
stop_sniffing = False

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global stop_sniffing
    print("\n[!] Stopping packet capture...")
    stop_sniffing = True

def print_packet(packet):
    """Callback function to process and display packets"""
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            # Get protocol name
            if protocol == 6:
                proto_name = "TCP"
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    info = f"Ports: {sport} -> {dport}"
            elif protocol == 17:
                proto_name = "UDP"
                if UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"Ports: {sport} -> {dport}"
            elif protocol == 1:
                proto_name = "ICMP"
                info = "ICMP Packet"
            else:
                proto_name = f"Other({protocol})"
                info = ""
            
            # Print packet info
            print(f"[{proto_name}] {ip_src:20} -> {ip_dst:20} {info}")
            
            # Show payload for small packets (optional)
            if Raw in packet and len(packet[Raw].load) < 100:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.strip():
                        print(f"    Payload: {payload[:80]}...")
                except:
                    pass
            
            print("-" * 60)
            
    except Exception as e:
        print(f"[Error processing packet: {e}]")

def start_sniffing(interface=None, count=0, filter_exp=""):
    """Start packet sniffing"""
    print("[*] Starting packet sniffer...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        # Set up signal handler for Ctrl+C
        signal.signal(signal.SIGINT, signal_handler)
        
        # Start sniffing
        if interface:
            print(f"[*] Listening on interface: {interface}")
            sniff(
                iface=interface,
                prn=print_packet,
                store=False,
                count=count if count > 0 else None,
                stop_filter=lambda x: stop_sniffing,
                filter=filter_exp
            )
        else:
            print("[*] Using default interface")
            sniff(
                prn=print_packet,
                store=False,
                count=count if count > 0 else None,
                stop_filter=lambda x: stop_sniffing,
                filter=filter_exp
            )
            
    except PermissionError:
        print("[!] Error: Need root/admin privileges to sniff packets!")
        print("[!] On Linux/Mac: Use 'sudo python3 packet_sniffer.py'")
        print("[!] On Windows: Run as Administrator")
    except Exception as e:
        print(f"[!] Error: {e}")

def list_interfaces():
    """List available network interfaces"""
    print("[*] Available network interfaces:")
    print("-" * 40)
    
    try:
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        
        print("\n[*] To find your active interface:")
        print("    - Windows: Usually 'Ethernet' or 'Wi-Fi'")
        print("    - Linux: Usually 'eth0' or 'wlan0'")
        print("    - Mac: Usually 'en0' or 'en1'")
        
    except Exception as e:
        print(f"[!] Error listing interfaces: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Simple Network Packet Sniffer - Educational Purpose Only",
        epilog="Example: sudo python3 packet_sniffer.py -i eth0 -c 100 -f 'tcp port 80'"
    )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (default: auto-detect)"
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
        help="BPF filter (e.g., 'tcp port 80', 'udp', 'icmp')"
    )
    
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List available network interfaces"
    )
    
    args = parser.parse_args()
    
    if args.list:
        list_interfaces()
        return
    
    # Check if running with privileges
    if os.name == 'posix' and os.geteuid() != 0:
        print("[!] Warning: May need root privileges for full packet capture")
        print("[!] Consider running with: sudo python3 packet_sniffer.py")
        print("[*] Continuing with limited capabilities...\n")
    
    print("\n" + "="*60)
    print("SIMPLE PACKET SNIFFER - EDUCATIONAL USE ONLY")
    print("="*60)
    
    if args.filter:
        print(f"[*] Filter: {args.filter}")
    if args.count > 0:
        print(f"[*] Packet count limit: {args.count}")
    
    start_sniffing(args.interface, args.count, args.filter)

if __name__ == "__main__":
    main()