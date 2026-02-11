# Universal Packet Sniffer

A cross-platform packet sniffer that works on **Windows (NO Npcap required)**, Linux, and macOS. Built for educational purposes to understand network protocols and packet analysis.

## 🚨 Important Legal Notice

**This tool is for EDUCATIONAL PURPOSES ONLY!**
- Only use on networks you own or have explicit permission to monitor
- Unauthorized packet sniffing may be illegal in your jurisdiction
- The author is not responsible for any misuse of this software

## ✨ Features

- **Windows**: Uses raw sockets - NO NPCAP/WinPcap required!
- **Linux/macOS**: Full Ethernet frame capture via AF_PACKET
- **Protocol Parsing**: TCP, UDP, ICMP, IP, Ethernet headers
- **Real-time Display**: Source/destination IPs, ports, MAC addresses, TCP flags
- **Basic Filtering**: Filter by protocol (tcp, udp, icmp)
- **Cross-platform**: Same codebase works on all major OSes

## 📋 Requirements

- **Python 3.6+**
- **Admin/root privileges** (required for raw sockets)
- No external libraries needed! (Scapy in requirements.txt is optional)

## 🚀 Quick Start

### Windows (No Npcap!)
# Run as Administrator
python packet_sniffer.py
python packet_sniffer.py -f udp
python packet_sniffer.py -c 50 -f icmp
