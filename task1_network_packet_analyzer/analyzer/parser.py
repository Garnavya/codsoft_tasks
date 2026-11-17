"""Packet Dissection and Feature Extraction Engine.

File: analyzer/parser.py
Purpose: Parses raw Scapy packet structures into normalized, strongly-typed
dictionaries containing key network, transport, and application layer attributes.
How it fits: Serves as the core data normalization layer between packet capture
(capture.py) and data presentation/export (formatter.py, stats.py).
Author: CodSoft Cyber Security Intern
How to run: Imported by packet_analyzer.py or tested via tests/test_parser.py.

LEARNING NOTE:
Packet analysis follows the OSI / TCP-IP layered model. A network packet is encapsulated:
Link Layer (Ethernet/ARP) -> Internet Layer (IPv4/IPv6) -> Transport Layer (TCP/UDP/ICMP)
-> Application Layer (DNS/HTTP/TLS). Dissection involves inspecting each header layer
in sequential order.
"""

import datetime
from typing import Any, Dict, Optional, Tuple
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet, Raw

from analyzer.protocols import (
    decode_tcp_flags,
    get_protocol_name,
    get_service_name,
)


def format_hex_ascii_dump(data: bytes, max_len: int = 64) -> str:
    """Format raw payload bytes into a classic hex and printable ASCII representation.

    Args:
        data: Raw byte payload extracted from the packet.
        max_len: Maximum number of bytes to preview (default 64).

    Returns:
        Formatted string containing space-separated hex bytes and ASCII representation.

    LEARNING NOTE:
    In digital forensics and malware traffic analysis, inspecting the initial bytes of a
    payload reveals magic bytes (file signatures like 'MZ' or 'PK'), plaintext protocols,
    or encoded command-and-control (C2) tokens.
    """
    if not data:
        return "<Empty Payload>"

    truncated = data[:max_len]
    hex_part = " ".join(f"{b:02x}" for b in truncated)
    # Printable ASCII range: 0x20 (space) to 0x7E (~)
    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in truncated)

    suffix = f" ... ({len(data)} bytes total)" if len(data) > max_len else ""
    return f"HEX: {hex_part}\nASCII: {ascii_part}{suffix}"


def extract_app_layer_hints(packet: Packet, payload_bytes: bytes) -> str:
    """Detect application layer protocols and extract human-friendly context hints.

    Args:
        packet: The Scapy Packet instance.
        payload_bytes: Extracted raw application payload bytes.

    Returns:
        String summary of application layer inspection.

    LEARNING NOTE:
    Deep Packet Inspection (DPI) checks beyond port numbers to identify application content.
    When TLS (HTTPS/port 443) is used, payload bytes are cryptographically opaque, protecting
    confidentiality. In contrast, plaintext HTTP/DNS exposes query names and URLs directly.
    """
    # 1. DNS Inspection
    if packet.haslayer(DNS):
        dns_layer = packet.getlayer(DNS)
        if dns_layer.qr == 0 and dns_layer.haslayer(DNSQR):
            qname = dns_layer.getlayer(DNSQR).qname
            qname_str = qname.decode(errors="ignore").rstrip(".") if isinstance(qname, bytes) else str(qname)
            return f"DNS Query: {qname_str}"
        elif dns_layer.qr == 1:
            ancount = getattr(dns_layer, "ancount", 0)
            return f"DNS Response (Answers: {ancount})"

    # 2. HTTP Inspection (Heuristic / Port 80 / 8080 or ASCII HTTP keywords)
    if payload_bytes:
        try:
            head = payload_bytes[:256].decode("latin-1")
            http_methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ")
            if head.startswith(http_methods) or "HTTP/1." in head:
                first_line = head.split("\r\n")[0]
                host_line = ""
                for line in head.split("\r\n"):
                    if line.lower().startswith("host:"):
                        host_line = f" [{line.strip()}]"
                        break
                return f"HTTP Request: {first_line}{host_line}"
            elif head.startswith("HTTP/1.0 ") or head.startswith("HTTP/1.1 "):
                status_line = head.split("\r\n")[0]
                return f"HTTP Response: {status_line}"
        except Exception:
            pass

    # 3. TLS / HTTPS Note
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        if tcp.sport == 443 or tcp.dport == 443:
            return "TLS/HTTPS (Encrypted Session Data)"

    return ""


def parse_packet(packet: Packet) -> Dict[str, Any]:
    """Parse a single Scapy packet into a standardized dictionary record.

    Args:
        packet: Scapy Packet instance captured from network or read from PCAP.

    Returns:
        Structured dictionary containing:
            - timestamp: ISO 8601 string
            - length: Packet size in bytes
            - protocol: String protocol name (TCP, UDP, ICMP, ARP, etc.)
            - src_ip: Source IP or MAC address
            - dst_ip: Destination IP or MAC address
            - src_port: Source port or None
            - dst_port: Destination port or None
            - service: Known service name or None
            - ttl: Time-To-Live integer or None
            - tcp_flags: List of decoded flag strings
            - payload_len: Byte length of transport/raw payload
            - payload_preview: Formatted hex/ascii representation
            - app_hint: Application layer context string
            - raw_summary: Scapy one-line summary
    """
    # Packet timestamp
    pkt_time = float(getattr(packet, "time", datetime.datetime.now().timestamp()))
    iso_time = datetime.datetime.fromtimestamp(pkt_time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    record: Dict[str, Any] = {
        "timestamp": iso_time,
        "length": len(packet),
        "protocol": "OTHER",
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "src_port": None,
        "dst_port": None,
        "service": None,
        "ttl": None,
        "tcp_flags": [],
        "payload_len": 0,
        "payload_preview": "<Empty>",
        "app_hint": "",
        "raw_summary": packet.summary(),
    }

    raw_payload = bytes()
    if packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)
    record["payload_len"] = len(raw_payload)
    record["payload_preview"] = format_hex_ascii_dump(raw_payload, max_len=64)

    # 1. ARP Handling (Address Resolution Protocol - Layer 2)
    # LEARNING NOTE:
    # ARP operates at the data link layer to map IP addresses to physical MAC addresses.
    # Because ARP packets lack an IP header, source/destination IPs must be extracted from
    # the ARP layer directly.
    if packet.haslayer(ARP):
        arp = packet[ARP]
        record["protocol"] = "ARP"
        record["src_ip"] = f"{arp.psrc} ({arp.hwsrc})"
        record["dst_ip"] = f"{arp.pdst} ({arp.hwdst})"
        op_desc = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"Op-{arp.op}"
        record["app_hint"] = f"ARP {op_desc} for {arp.pdst}"
        return record

    # 2. IP Layer Handling (IPv4 - Layer 3)
    if packet.haslayer(IP):
        ip = packet[IP]
        record["src_ip"] = ip.src
        record["dst_ip"] = ip.dst
        record["ttl"] = ip.ttl
        record["protocol"] = get_protocol_name(ip.proto)

        # LEARNING NOTE:
        # Time-to-Live (TTL) is decremented by every routing hop to prevent infinite loops.
        # Initial TTL values differ by OS (Windows typically defaults to 128, Linux/Unix to 64).
        # This is a classic passive OS fingerprinting technique.

    # 3. Transport Layer Handling (Layer 4)
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        record["protocol"] = "TCP"
        record["src_port"] = int(tcp.sport)
        record["dst_port"] = int(tcp.dport)
        record["tcp_flags"] = decode_tcp_flags(tcp.flags)
        record["service"] = get_service_name(tcp.dport) or get_service_name(tcp.sport)

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        record["protocol"] = "UDP"
        record["src_port"] = int(udp.sport)
        record["dst_port"] = int(udp.dport)
        record["service"] = get_service_name(udp.dport) or get_service_name(udp.sport)

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        record["protocol"] = "ICMP"
        type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
        icmp_type = type_names.get(icmp.type, f"Type {icmp.type}")
        record["app_hint"] = f"ICMP {icmp_type} (Code {icmp.code})"

    # Extract higher level application hints (DNS, HTTP, TLS)
    app_hint = extract_app_layer_hints(packet, raw_payload)
    if app_hint:
        record["app_hint"] = app_hint

    return record
