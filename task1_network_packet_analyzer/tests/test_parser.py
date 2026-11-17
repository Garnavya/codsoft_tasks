"""Unit Tests for Network Packet Analyzer.

File: tests/test_parser.py
Purpose: Validates packet dissection, TCP flag decoding, protocol translation,
statistical telemetry aggregation, and file export routines using synthesized packets.
How it fits: Quality assurance and regression testing suite for Task 1.
Author: CodSoft Cyber Security Intern
How to run:
    pytest task1_network_packet_analyzer/tests/test_parser.py -v
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure analyzer package is resolvable regardless of test working directory
TASK1_DIR = Path(__file__).resolve().parent.parent
if str(TASK1_DIR) not in sys.path:
    sys.path.insert(0, str(TASK1_DIR))

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from analyzer.formatter import export_to_csv, export_to_json
from analyzer.parser import (
    extract_app_layer_hints,
    format_hex_ascii_dump,
    parse_packet,
)
from analyzer.protocols import (
    decode_tcp_flags,
    get_protocol_name,
    get_service_name,
)
from analyzer.stats import CaptureStatistics


# ============================================================================
# Protocol & Port Lookup Tests
# ============================================================================

def test_protocol_resolution():
    """Verify standard IP protocol numbers map to expected string identifiers."""
    assert get_protocol_name(1) == "ICMP"
    assert get_protocol_name(6) == "TCP"
    assert get_protocol_name(17) == "UDP"
    assert get_protocol_name(999) == "PROTO-999"


def test_service_port_resolution():
    """Verify well-known ports resolve to corresponding application services."""
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(53) == "DNS"
    assert get_service_name(22) == "SSH"
    assert get_service_name(49152) is None


def test_tcp_flag_decoding():
    """Verify TCP control flags decode accurately into ordered lists."""
    assert decode_tcp_flags("S") == ["SYN"]
    assert decode_tcp_flags("SA") == ["SYN", "ACK"]
    assert decode_tcp_flags("PA") == ["PSH", "ACK"]
    assert decode_tcp_flags("FA") == ["FIN", "ACK"]
    assert decode_tcp_flags("R") == ["RST"]


# ============================================================================
# Packet Dissection Tests
# ============================================================================

def test_parse_tcp_syn_packet():
    """Validate extraction of TCP connection establishment packet attributes."""
    pkt = (
        IP(src="192.168.1.50", dst="10.0.0.1", ttl=64)
        / TCP(sport=51234, dport=80, flags="S", seq=100)
    )
    record = parse_packet(pkt)

    assert record["protocol"] == "TCP"
    assert record["src_ip"] == "192.168.1.50"
    assert record["dst_ip"] == "10.0.0.1"
    assert record["src_port"] == 51234
    assert record["dst_port"] == 80
    assert record["service"] == "HTTP"
    assert record["ttl"] == 64
    assert "SYN" in record["tcp_flags"]


def test_parse_udp_dns_packet():
    """Validate extraction of DNS query attributes over UDP."""
    pkt = (
        IP(src="192.168.1.50", dst="8.8.8.8", ttl=128)
        / UDP(sport=55000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="test.local"))
    )
    record = parse_packet(pkt)

    assert record["protocol"] == "UDP"
    assert record["src_ip"] == "192.168.1.50"
    assert record["dst_ip"] == "8.8.8.8"
    assert record["dst_port"] == 53
    assert record["service"] == "DNS"
    assert "DNS Query: test.local" in record["app_hint"]


def test_parse_icmp_echo_packet():
    """Validate extraction of ICMP ping request attributes."""
    pkt = (
        IP(src="192.168.1.1", dst="192.168.1.2")
        / ICMP(type=8, code=0)
        / Raw(load=b"pingtestpayload")
    )
    record = parse_packet(pkt)

    assert record["protocol"] == "ICMP"
    assert "Echo Request" in record["app_hint"]
    assert record["payload_len"] == len(b"pingtestpayload")


def test_parse_arp_packet():
    """Validate Layer-2 ARP packet parsing and MAC/IP pairing."""
    pkt = Ether() / ARP(
        op=1,
        psrc="192.168.1.1",
        pdst="192.168.1.100",
        hwsrc="aa:bb:cc:dd:ee:01",
        hwdst="00:00:00:00:00:00",
    )
    record = parse_packet(pkt)

    assert record["protocol"] == "ARP"
    assert "192.168.1.1" in record["src_ip"]
    assert "192.168.1.100" in record["dst_ip"]
    assert "ARP Request" in record["app_hint"]


def test_http_hint_extraction():
    """Validate HTTP method and header extraction from plaintext TCP payloads."""
    payload = b"GET /admin/login HTTP/1.1\r\nHost: intranet.corp\r\n\r\n"
    pkt = (
        IP(src="10.0.0.5", dst="10.0.0.10")
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(load=payload)
    )
    record = parse_packet(pkt)

    assert "HTTP Request: GET /admin/login HTTP/1.1" in record["app_hint"]
    assert "intranet.corp" in record["app_hint"]


def test_payload_hex_ascii_dump():
    """Verify hex and printable ASCII preview formatting."""
    data = b"Hello\x00World\xff!"
    preview = format_hex_ascii_dump(data, max_len=16)

    assert "HEX: 48 65 6c 6c 6f 00 57 6f 72 6c 64 ff 21" in preview
    assert "ASCII: Hello.World.!" in preview


# ============================================================================
# Statistical Aggregation Tests
# ============================================================================

def test_statistics_aggregation():
    """Verify statistical counters, top talkers, and protocol distribution."""
    stats = CaptureStatistics()

    pkt1 = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80, flags="S"))
    pkt2 = parse_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80, flags="A"))
    pkt3 = parse_packet(IP(src="3.3.3.3", dst="2.2.2.2") / UDP(sport=2000, dport=53))

    stats.update(pkt1)
    stats.update(pkt2)
    stats.update(pkt3)

    summary = stats.to_dict()
    assert summary["total_packets"] == 3
    assert summary["protocol_breakdown"]["TCP"] == 2
    assert summary["protocol_breakdown"]["UDP"] == 1
    assert summary["top_source_ips"][0]["ip"] == "1.1.1.1"
    assert summary["top_source_ips"][0]["count"] == 2


# ============================================================================
# Export Functionality Tests
# ============================================================================

def test_export_json_and_csv():
    """Verify JSON and CSV export generators produce valid files on disk."""
    stats = CaptureStatistics()
    pkt = parse_packet(IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="S"))
    stats.update(pkt)
    records = [pkt]

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "test.json")
        csv_path = os.path.join(tmpdir, "test.csv")

        export_to_json(records, stats, json_path)
        assert os.path.exists(json_path)
        assert os.path.getsize(json_path) > 50

        export_to_csv(records, csv_path)
        assert os.path.exists(csv_path)
        assert os.path.getsize(csv_path) > 30
