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

## 💻 Possible Sniffing Commands

### 🪟 Windows (Run as Administrator)

#### Capture all supported traffic (UDP, ICMP, outgoing TCP)
python packet_sniffer.py

#### Capture only UDP packets
python packet_sniffer.py -f udp

#### Capture only ICMP packets (ping)
python packet_sniffer.py -f icmp

#### Capture only TCP packets (outgoing only)
python packet_sniffer.py -f tcp

#### Capture 50 packets only
python packet_sniffer.py -c 50

#### Capture 100 UDP packets
python packet_sniffer.py -c 100 -f udp

#### List available network interfaces
python packet_sniffer.py -l

### 🐧 Linux / 🍎 macOS (Run as root)

#### Capture all traffic on default interface
sudo python3 packet_sniffer.py

#### Capture traffic on a specific interface
sudo python3 packet_sniffer.py -i eth0
sudo python3 packet_sniffer.py -i wlan0

#### Capture only UDP packets
sudo python3 packet_sniffer.py -i eth0 -f udp

#### Capture only TCP packets
sudo python3 packet_sniffer.py -i eth0 -f tcp

#### Capture only ICMP packets
sudo python3 packet_sniffer.py -i eth0 -f icmp

#### Limit capture to 100 packets
sudo python3 packet_sniffer.py -i eth0 -c 100

#### List available interfaces
sudo python3 packet_sniffer.py -l


