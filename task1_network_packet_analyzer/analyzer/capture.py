"""Packet Capture and Ingestion Subsystem.

File: analyzer/capture.py
Purpose: Provides offline PCAP ingestion and live packet capture capabilities via Scapy.
Detects missing Windows prerequisites (Npcap driver and Administrator privileges)
and emits actionable diagnostic advice rather than crashing with unhandled exceptions.
How it fits: Serves as the packet acquisition engine for packet_analyzer.py.
Author: CodSoft Cyber Security Intern
How to run: Imported by packet_analyzer.py.

LEARNING NOTE:
Packet capturing on Windows requires a kernel-mode driver (Npcap) to hook into the
Network Driver Interface Specification (NDIS). Raw sockets without Npcap cannot capture
promiscuous or full transport packets on modern Windows editions. Administrative elevation
is mandatory to access network adapters in promiscuous mode.
"""

import ctypes
import os
import platform
import sys
from typing import Callable, Generator, List, Optional, Tuple
from scapy.all import conf, get_if_list, rdpcap, sniff, wrpcap
from scapy.packet import Packet


def is_running_as_admin() -> bool:
    """Check if the current process is running with administrative elevation.

    Returns:
        True if running with Administrator privileges, False otherwise.
    """
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        # On Linux/Unix, UID 0 corresponds to root
        return os.geteuid() == 0  # type: ignore[attr-defined]


def is_npcap_installed() -> bool:
    """Verify whether Npcap or WinPcap driver DLLs are available on Windows.

    Returns:
        True if packet capture libraries are present, False otherwise.
    """
    if platform.system().lower() != "windows":
        return True

    # Common system locations for Npcap / WinPcap libraries
    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidate_paths = [
        os.path.join(windir, "System32", "wpcap.dll"),
        os.path.join(windir, "SysWOW64", "wpcap.dll"),
        os.path.join(windir, "System32", "Npcap", "wpcap.dll"),
        os.path.join(windir, "System32", "Packet.dll"),
    ]
    return any(os.path.exists(path) for path in candidate_paths)


def get_available_interfaces() -> List[str]:
    """Retrieve the list of active network interface names.

    Returns:
        List of interface identifier strings.
    """
    try:
        return get_if_list()
    except Exception as exc:
        return [f"Error querying interfaces: {exc}"]


def check_live_capture_prerequisites() -> Tuple[bool, str]:
    """Validate that the operating environment can perform live promiscuous captures.

    Returns:
        Tuple of (is_ready: bool, diagnostic_message: str).
    """
    if platform.system().lower() == "windows":
        if not is_npcap_installed():
            msg = (
                "[!] Npcap driver not detected on this Windows system.\n"
                "    Live packet capture requires Npcap to interact with network hardware.\n"
                "    Fix:\n"
                "      1. Download and install Npcap from: https://npcap.com/\n"
                "      2. During setup, check 'Install Npcap in WinPcap API-compatible Mode'.\n"
                "    TIP: You can immediately test and analyze captures without Npcap\n"
                "    using the offline flag: python packet_analyzer.py --read-pcap samples/sample_traffic.pcap"
            )
            return False, msg

        if not is_running_as_admin():
            msg = (
                "[!] Administrator privileges required for live packet capture.\n"
                "    Windows restricts promiscuous socket access to elevated accounts.\n"
                "    Fix:\n"
                "      Right-click PowerShell or Windows Terminal -> 'Run as Administrator'.\n"
                "    TIP: You can immediately analyze offline PCAP files without elevation:\n"
                "    python packet_analyzer.py --read-pcap samples/sample_traffic.pcap"
            )
            return False, msg

    return True, "Environment ready for live capture."


def read_pcap_file(filepath: str) -> List[Packet]:
    """Load packets from a standard .pcap or .pcapng capture file.

    Args:
        filepath: Filesystem path to the capture file.

    Returns:
        List of Scapy Packet objects.

    Raises:
        FileNotFoundError: If the specified PCAP file does not exist.
        ValueError: If Scapy fails to parse the file format.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    try:
        packets = rdpcap(filepath)
        return list(packets)
    except Exception as exc:
        raise ValueError(f"Failed to read PCAP file '{filepath}': {exc}") from exc


def capture_live_packets(
    interface: Optional[str] = None,
    count: int = 0,
    timeout: Optional[int] = None,
    bpf_filter: str = "",
    packet_callback: Optional[Callable[[Packet], None]] = None,
    save_path: Optional[str] = None,
) -> List[Packet]:
    """Execute live packet capture with optional BPF filtering and streaming callbacks.

    Args:
        interface: Specific network adapter name or None for default.
        count: Maximum number of packets to capture (0 for infinite until timeout).
        timeout: Duration in seconds to capture before stopping.
        bpf_filter: Berkeley Packet Filter expression (e.g., 'tcp port 80', 'icmp').
        packet_callback: Function invoked per captured packet for live streaming.
        save_path: Optional path to write raw captured packets as .pcap.

    Returns:
        List of captured Packet instances.

    LEARNING NOTE:
    Berkeley Packet Filters (BPF) operate in kernel space, filtering uninteresting packets
    before copying memory to user space. This drastically reduces CPU overhead during
    high-throughput network monitoring.
    """
    captured: List[Packet] = []

    def _internal_callback(pkt: Packet) -> None:
        captured.append(pkt)
        if packet_callback:
            packet_callback(pkt)

    sniff(
        iface=interface,
        count=count,
        timeout=timeout,
        filter=bpf_filter if bpf_filter else None,
        prn=_internal_callback,
        store=False if save_path is None and packet_callback else True,
    )

    if save_path and captured:
        wrpcap(save_path, captured)

    return captured
