"""Protocol & Port Lookup Utilities.

File: analyzer/protocols.py
Purpose: Translates raw transport/application port numbers and protocol codes into
human-readable names and decodes TCP control flags into structured representations.
How it fits: Imported by analyzer/parser.py to enrich low-level packet data.
Author: CodSoft Cyber Security Intern
How to run: Automatically imported by packet_analyzer.py or tests.

LEARNING NOTE:
At the network and transport layers, protocols and services are represented by numeric
identifiers (IP protocol numbers and transport port numbers). Translating these to
standard names (e.g., TCP port 53 -> DNS) allows security analysts to quickly infer
traffic intent.
"""

from typing import Dict, List, Optional

# Standard IP Protocol Numbers (Assigned by IANA)
IP_PROTOCOLS: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

# Common Well-Known & Registered Ports (0-1023 well-known, 1024-49151 registered)
COMMON_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

# TCP Control Flags Mapping
# LEARNING NOTE:
# The TCP header contains 9 1-bit flags used to manage connection state.
# SYN starts a handshake, ACK confirms reception, FIN requests graceful closure,
# and RST forcibly tears down an invalid or rejected connection.
TCP_FLAG_NAMES: Dict[str, str] = {
    "F": "FIN",  # Finish (graceful teardown)
    "S": "SYN",  # Synchronize sequence numbers (connection initiation)
    "R": "RST",  # Reset (abrupt connection termination)
    "P": "PSH",  # Push function (deliver data immediately without buffering)
    "A": "ACK",  # Acknowledgment field is significant
    "U": "URG",  # Urgent pointer field is significant
    "E": "ECE",  # ECN-Echo (congestion notification)
    "C": "CWR",  # Congestion Window Reduced
}


def get_protocol_name(proto_num: int) -> str:
    """Resolve an IP protocol number to its human-readable acronym.

    Args:
        proto_num: Numeric IP protocol code (e.g., 6 for TCP, 17 for UDP).

    Returns:
        Standard string acronym (e.g., 'TCP', 'UDP') or 'PROTO-<num>' if unknown.
    """
    return IP_PROTOCOLS.get(proto_num, f"PROTO-{proto_num}")


def get_service_name(port: int) -> Optional[str]:
    """Resolve a well-known TCP/UDP port number to its common service name.

    Args:
        port: Integer port number (0-65535).

    Returns:
        Service name string (e.g., 'HTTP', 'DNS') or None if not well-known.
    """
    return COMMON_PORTS.get(port, None)


def decode_tcp_flags(flags_val) -> List[str]:
    """Decode Scapy TCP flags into an ordered list of flag names.

    Args:
        flags_val: Scapy FlagValue or string representation of TCP flags.

    Returns:
        List of decoded flag strings (e.g., ['SYN', 'ACK']).

    LEARNING NOTE:
    In network defense and intrusion detection (NIDS), analyzing flag combinations
    helps identify port scans (e.g., SYN scans, NULL scans with no flags set,
    or Xmas scans with FIN, PSH, and URG set simultaneously).
    """
    flag_str = str(flags_val)
    decoded: List[str] = []
    for char in flag_str:
        if char in TCP_FLAG_NAMES:
            decoded.append(TCP_FLAG_NAMES[char])
        elif char not in (" ", ""):
            decoded.append(f"FLAG({char})")
    return decoded
