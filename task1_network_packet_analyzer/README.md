# Task 1: Network Packet Analyzer

A modular, defensive network packet analysis engine developed in Python using Scapy and Rich. Designed for security analysts, network engineers, and students to inspect protocol behaviors, dissect packet headers and payloads, and profile traffic patterns across OSI Layers 2 through 7.

---

## 1. Project Objective

To understand and inspect computer network communications at the packet level. This tool decodes raw network frames, extracts transport and application layer metadata, previews unencrypted and encrypted payloads, and computes traffic intelligence metrics (such as protocol distribution and top talkers) in an intuitive, color-coded terminal interface.

---

## 2. Key Features

- **Multi-Protocol Dissection:** Parses Ethernet, ARP, IPv4, TCP, UDP, ICMP, DNS, HTTP, and TLS traffic.
- **Deep Header Inspection:** Extracts IP addresses, ports, Time-To-Live (TTL), sequence numbers, and decoded TCP control flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **Forensic Payload Inspection:** Previews the initial 64 bytes of payload in a dual Hex / printable ASCII format.
- **Application Context Heuristics:** Detects DNS query names/answers, extracts unencrypted HTTP request methods and Host headers, and notes TLS-encrypted sessions.
- **Traffic Intelligence & Statistics:** Tracks session volume, duration, packet rates, protocol breakdown percentages, top transmitting talkers, and top destination ports.
- **Flexible Exporting:** Saves structured forensic records to CSV and JSON formats for SIEM ingestion or spreadsheet analysis.
- **Windows-Optimized & Resilient:** Detects missing Npcap drivers and unprivileged user shells, providing actionable guidance instead of crashing.
- **Synthetic Traffic Generator:** Generates realistic, reproducible `.pcap` files containing multi-protocol conversations for continuous testing without live network capture dependencies.

---

## 3. Architecture & Data Flow

```
[ Live Network Adapter / Offline PCAP ]
                  │
                  ▼
         [ analyzer/capture.py ]
   (Elevation & Npcap Check, Scapy Sniff/rdpcap)
                  │
                  ▼
         [ analyzer/parser.py ] ◄─── [ analyzer/protocols.py ]
   (Extract IP, Ports, Flags,          (Port/Proto Lookup &
    Hex/ASCII Payload, App Hints)       TCP Flag Bitmasks)
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
[ analyzer/stats.py ]    [ analyzer/formatter.py ]
  (Counters, Top-N,        (Rich Table, Hex Dump,
   Rate & Metrics)          JSON & CSV Exporters)
```

---

## 4. Mapping to CodSoft Requirements

| CodSoft Specification | Implementation in Repository | Relevant Files |
| :--- | :--- | :--- |
| **Capture packets using Python** | Implemented using Scapy with BPF filtering, timeout limits, and packet counters. Provides raw socket fallback awareness. | `packet_analyzer.py`, `analyzer/capture.py` |
| **Inspect packets to understand protocol behavior** | Layered dissection covering ARP, IP, ICMP, TCP, UDP, DNS, and HTTP. Decodes TCP 3-way handshakes and connection teardowns. | `analyzer/parser.py`, `analyzer/protocols.py` |
| **Extract source IP, destination IP, protocol type, and payload** | Structured record extraction capturing source/dest IPs, transport ports, protocol names, TTL, and hex/ASCII payload dumps. | `analyzer/parser.py` (`parse_packet()`) |
| **Present output in a clear, organized format** | Color-coded Rich terminal tables, verbose inspector views, summary panels, and JSON/CSV export files. | `analyzer/formatter.py` |

---

## 5. Prerequisites & Installation

### Windows 10/11 (Recommended Environment)
1. Ensure **Python 3.10+** is installed.
2. For **live packet capture** on Windows, install the **Npcap** driver:
   - Download installer from [https://npcap.com/](https://npcap.com/)
   - During setup, enable: **"Install Npcap in WinPcap API-compatible Mode"**.
   - Open PowerShell as **Administrator**.
3. *Note:* If you do not have Administrator rights or Npcap installed, you can use the included synthetic PCAP capture (`samples/sample_traffic.pcap`), which works 100% out of the box without special drivers!

### Setup Virtual Environment
```powershell
# Navigate to repository root
cd c:\Users\garna\Desktop\codsoft_tasks

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install pinned dependencies
pip install -r requirements.txt
```

---

## 6. Usage Guide & Example Commands

### Generate Synthetic Sample Traffic (Demo Mode)
Before running the analyzer, generate the multi-protocol synthetic capture:
```powershell
python task1_network_packet_analyzer/samples/generate_sample_pcap.py
```

### Analyze Offline PCAP Capture
```powershell
cd task1_network_packet_analyzer

# Standard table view
python packet_analyzer.py --read-pcap samples/sample_traffic.pcap

# Verbose inspection with payload hex dumps
python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --verbose

# Export capture analysis to JSON
python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --export json --output output/analysis.json

# Export capture analysis to CSV
python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --export csv --output output/analysis.csv
```

### List Available Network Interfaces
```powershell
python packet_analyzer.py --list-interfaces
```

### Live Capture (Requires Admin PowerShell + Npcap)
```powershell
# Capture 10 packets on default adapter
python packet_analyzer.py --count 10

# Capture only HTTP traffic for 15 seconds
python packet_analyzer.py --timeout 15 --filter "tcp port 80"

# Capture and simultaneously save raw PCAP for Wireshark
python packet_analyzer.py --count 20 --save-pcap output/live_session.pcap
```

---

## 7. Sample Terminal Output

```
╔══════════════════════════════════════════════════════════════════════╗
║            CodSoft Cyber Security: Network Packet Analyzer           ║
╚══════════════════════════════════════════════════════════════════════╝
► ETHICS & LEGAL NOTICE: This tool is intended strictly for authorized educational
  network analysis, diagnostic inspection, and security defense research.
  Do NOT capture traffic on networks without explicit, documented permission.

► Ingesting offline PCAP file: samples/sample_traffic.pcap

                        Captured Network Packets
┌───┬─────────────────────┬──────┬─────────────────┬──────────────────┬───────────────────┬──────────────────────────────────────────┬─────┐
│ # │ Timestamp           │ Proto│ Source Address  │ Destination Addr │ Port/Service      │ Flags / Info                             │ Len │
├───┼─────────────────────┼──────┼─────────────────┼──────────────────┼───────────────────┼──────────────────────────────────────────┼─────┤
│ 1 │ 2026-11-17 21:00:00 │ ARP  │ 192.168.1.100   │ 192.168.1.1      │ -                 │ ARP Request for 192.168.1.1              │ 42B │
│ 2 │ 2026-11-17 21:00:00 │ ARP  │ 192.168.1.1     │ 192.168.1.100    │ -                 │ ARP Reply for 192.168.1.100              │ 42B │
│ 3 │ 2026-11-17 21:00:00 │ UDP  │ 192.168.1.100   │ 1.1.1.1          │ 54321 -> 53 (DNS) │ DNS Query: example.com                   │ 57B │
│ 4 │ 2026-11-17 21:00:00 │ TCP  │ 192.168.1.100   │ 93.184.216.34    │ 49152 -> 80 (HTTP)│ [SYN]                                    │ 54B │
│ 5 │ 2026-11-17 21:00:00 │ TCP  │ 93.184.216.34   │ 192.168.1.100    │ 80 -> 49152 (HTTP)│ [SYN,ACK]                                │ 54B │
│ 6 │ 2026-11-17 21:00:00 │ TCP  │ 192.168.1.100   │ 93.184.216.34    │ 49152 -> 80 (HTTP)│ [PSH,ACK] HTTP Request: GET /index.html  │ 174B│
│ 7 │ 2026-11-17 21:00:00 │ ICMP │ 192.168.1.100   │ 8.8.8.8          │ -                 │ ICMP Echo Request (Code 0)               │ 60B │
└───┴─────────────────────┴──────┴─────────────────┴──────────────────┴───────────────────┴──────────────────────────────────────────┴─────┘
```

---

## 8. Running the Unit Tests

Execute the automated pytest suite verifying dissection logic, protocol decoding, and export formatting:
```powershell
pytest task1_network_packet_analyzer/tests/test_parser.py -v
```

---

## 9. Ethics and Legal Disclaimer

> [!CAUTION]
> **Defensive and Educational Use Only**
> Packet sniffing tools capture raw transmission payloads, which may contain sensitive personal data, authorization cookies, and plaintext credentials on insecure networks. Sniffing packets on a computer network without explicit authorization from the network owner is illegal under cybercrime laws (including the US Computer Fraud and Abuse Act and the Indian Information Technology Act, 2000).
> 
> This tool does **not** include ARP spoofing, session hijacking, or credential harvesting capabilities. Always use it on private local loops, isolated lab subnets, or using pre-recorded synthetic capture files.

---

## 10. Technical Limitations & Future Work

- **Encrypted Payloads:** TLS (HTTPS, port 443) and SSH encrypt transport payloads. While the analyzer accurately parses TCP handshakes and records packet lengths, it cannot decrypt ciphertext without session keys (by design).
- **IPv6 Partial Support:** IPv6 address headers are recognized, but advanced extension headers are currently simplified.
- **Hardware Acceleration:** Live captures are processed in user space through Python. For multi-gigabit saturating line speeds, kernel-level tools like `eBPF` or `DPDK` are recommended.

---

## 11. What I Learned

1. **Protocol Encapsulation:** Visualizing how Layer 2 (Ethernet MAC) envelopes Layer 3 (IP), which envelopes Layer 4 (TCP/UDP), which encapsulates the application payload.
2. **TCP State Machine:** Observing how sequence numbers and flags (`SYN` -> `SYN/ACK` -> `ACK`) establish reliable full-duplex communication channels.
3. **Forensic Value of TTL:** How Time-To-Live reveals operating system fingerprints and hop distance.
4. **Handling Windows Privileges:** Gracefully detecting driver dependencies (Npcap) and privilege levels without causing abrupt program crashes.
