"""Synthetic PCAP Traffic Generator.

File: samples/generate_sample_pcap.py
Purpose: Synthesizes multi-protocol network packets (TCP 3-way handshake, HTTP, DNS,
ICMP ping, ARP resolution) and writes them to a standard .pcap file.
How it fits: Allows complete unit testing, continuous integration, and portfolio demos
without requiring live network access, root/admin elevation, or third-party drivers.
Author: CodSoft Cyber Security Intern
How to run:
    python samples/generate_sample_pcap.py

LEARNING NOTE:
In cybersecurity training and testing, synthetic packet captures provide deterministic,
repeatable test fixtures. They simulate realistic multi-layer communications while
ensuring zero privacy leaks and zero dependence on host network configurations.
"""

import os
import time
from pathlib import Path
from scapy.all import wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw


def generate_synthetic_pcap(output_path: str = None) -> str:
    """Construct realistic synthetic packets across multiple protocols and write to disk.

    Args:
        output_path: Target filesystem path for the output .pcap file.

    Returns:
        Absolute path to the created PCAP file.
    """
    if output_path is None:
        script_dir = Path(__file__).resolve().parent
        out_file = script_dir / "sample_traffic.pcap"
    else:
        out_file = Path(output_path)

    out_file.parent.mkdir(parents=True, exist_ok=True)

    base_time = time.time()
    packets = []

    # Standard MAC addresses for layer-2 consistency
    client_mac = "00:11:22:33:44:55"
    gateway_mac = "aa:bb:cc:dd:ee:ff"
    broadcast_mac = "ff:ff:ff:ff:ff:ff"

    # ---------------------------------------------------------
    # 1. ARP Resolution (Address Resolution Protocol - Layer 2)
    # ---------------------------------------------------------
    arp_req = Ether(dst=broadcast_mac, src=client_mac) / ARP(
        op=1,
        hwsrc=client_mac,
        psrc="192.168.1.100",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )
    arp_req.time = base_time + 0.001
    packets.append(arp_req)

    arp_rep = Ether(dst=client_mac, src=gateway_mac) / ARP(
        op=2,
        hwsrc=gateway_mac,
        psrc="192.168.1.1",
        hwdst=client_mac,
        pdst="192.168.1.100",
    )
    arp_rep.time = base_time + 0.003
    packets.append(arp_rep)

    # ---------------------------------------------------------
    # 2. DNS Query & Response (UDP Port 53)
    # ---------------------------------------------------------
    dns_query = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src="192.168.1.100", dst="1.1.1.1", ttl=64)
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_query.time = base_time + 0.010
    packets.append(dns_query)

    dns_resp = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src="1.1.1.1", dst="192.168.1.100", ttl=58)
        / UDP(sport=53, dport=54321)
        / DNS(
            qr=1,
            aa=0,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
        )
    )
    dns_resp.time = base_time + 0.025
    packets.append(dns_resp)

    # ---------------------------------------------------------
    # 3. TCP 3-Way Handshake (SYN -> SYN/ACK -> ACK)
    # ---------------------------------------------------------
    client_ip = "192.168.1.100"
    server_ip = "93.184.216.34"
    client_port = 49152
    server_port = 80

    tcp_syn = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    )
    tcp_syn.time = base_time + 0.050
    packets.append(tcp_syn)

    tcp_syn_ack = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=5000, ack=1001)
    )
    tcp_syn_ack.time = base_time + 0.070
    packets.append(tcp_syn_ack)

    tcp_ack = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=5001)
    )
    tcp_ack.time = base_time + 0.072
    packets.append(tcp_ack)

    # ---------------------------------------------------------
    # 4. HTTP Application Traffic (Plaintext Request & Response)
    # ---------------------------------------------------------
    http_req_payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html\r\n\r\n"
    )
    http_req = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001, ack=5001)
        / Raw(load=http_req_payload)
    )
    http_req.time = base_time + 0.080
    packets.append(http_req)

    http_resp_payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Server: ECS (dcb/7F83)\r\n"
        b"Content-Length: 45\r\n\r\n"
        b"<html><body><h1>Example Domain</h1></body></html>"
    )
    http_resp = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src=server_ip, dst=client_ip, ttl=56)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=5001, ack=1001 + len(http_req_payload))
        / Raw(load=http_resp_payload)
    )
    http_resp.time = base_time + 0.120
    packets.append(http_resp)

    # ---------------------------------------------------------
    # 5. ICMP Echo Request & Reply (Ping)
    # ---------------------------------------------------------
    icmp_req = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src="192.168.1.100", dst="8.8.8.8", ttl=128)
        / ICMP(type=8, code=0, id=0x1234, seq=1)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    )
    icmp_req.time = base_time + 0.150
    packets.append(icmp_req)

    icmp_rep = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src="8.8.8.8", dst="192.168.1.100", ttl=54)
        / ICMP(type=0, code=0, id=0x1234, seq=1)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    )
    icmp_rep.time = base_time + 0.170
    packets.append(icmp_rep)

    # ---------------------------------------------------------
    # 6. TLS / HTTPS Encrypted Traffic Simulation (Port 443)
    # ---------------------------------------------------------
    tls_packet = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst="104.16.132.229", ttl=64)
        / TCP(sport=50124, dport=443, flags="PA", seq=200, ack=300)
        / Raw(load=b"\x16\x03\x03\x00\x35\x01\x00\x00\x31\x03\x03" + os.urandom(32))
    )
    tls_packet.time = base_time + 0.200
    packets.append(tls_packet)

    # Write packets out to the PCAP file
    wrpcap(str(out_file), packets)
    return str(out_file.resolve())


if __name__ == "__main__":
    generated_path = generate_synthetic_pcap()
    print(f"[+] Synthetic PCAP generated successfully at: {generated_path}")
