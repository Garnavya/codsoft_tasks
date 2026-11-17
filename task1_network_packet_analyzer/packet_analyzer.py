#!/usr/bin/env python3
"""CodSoft Network Packet Analyzer - Main CLI Application.

File: packet_analyzer.py
Purpose: Command-line interface for capturing, dissecting, inspecting, and profiling
network packets across standard networking protocols (TCP, UDP, ICMP, DNS, ARP, HTTP).
Supports live network sniffing, offline PCAP forensics, BPF filtering, and JSON/CSV reporting.
How it fits: Root entrypoint for Task 1 of the CodSoft Cyber Security Internship portfolio.
Author: CodSoft Cyber Security Intern
How to run:
    # 1. Analyze sample synthetic traffic (No admin or Npcap required):
    python packet_analyzer.py --read-pcap samples/sample_traffic.pcap

    # 2. Verbose inspection with payload hex dumps:
    python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --verbose

    # 3. Export to JSON or CSV:
    python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --export json --output output/capture.json

    # 4. List network adapters:
    python packet_analyzer.py --list-interfaces

    # 5. Live capture with BPF filter (Requires Administrator + Npcap on Windows):
    python packet_analyzer.py --count 10 --filter "tcp port 80"

LEARNING NOTE:
Packet analysis is fundamental to network defense, security monitoring, and incident response.
Analyzing raw packet headers and payloads allows defenders to detect port scans, identify
unencrypted credential transmission, investigate command-and-control beacons, and isolate
denial-of-service traffic.
"""

import argparse
import sys
from pathlib import Path
from typing import List

# Ensure parent directory is in sys.path when invoked directly
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from analyzer.capture import (
    capture_live_packets,
    check_live_capture_prerequisites,
    get_available_interfaces,
    read_pcap_file,
)
from analyzer.formatter import (
    add_packet_row,
    console,
    create_packet_table,
    export_to_csv,
    export_to_json,
    print_banner,
    print_summary_statistics,
    print_verbose_packet,
)
from analyzer.parser import parse_packet
from analyzer.stats import CaptureStatistics


def parse_arguments() -> argparse.Namespace:
    """Configure and parse command-line arguments for the analyzer."""
    parser = argparse.ArgumentParser(
        prog="packet_analyzer.py",
        description="CodSoft Network Packet Analyzer - Defensive Packet Dissection & Profiling Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_analyzer.py --read-pcap samples/sample_traffic.pcap
  python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --verbose
  python packet_analyzer.py --read-pcap samples/sample_traffic.pcap --export csv --output output/report.csv
  python packet_analyzer.py --list-interfaces
  python packet_analyzer.py --count 20 --filter "ip proto \\icmp"
        """,
    )

    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface name or GUID to bind live capture to.",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Total packet count to capture before stopping (0 = continuous).",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Maximum capture duration in seconds.",
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default="",
        help="Berkeley Packet Filter (BPF) expression (e.g. 'tcp port 80', 'icmp').",
    )
    parser.add_argument(
        "-r", "--read-pcap",
        dest="read_pcap",
        type=str,
        default=None,
        help="Path to an offline PCAP/PCAPNG capture file to parse.",
    )
    parser.add_argument(
        "-s", "--save-pcap",
        dest="save_pcap",
        type=str,
        default=None,
        help="Path to write captured live packets into a raw PCAP file.",
    )
    parser.add_argument(
        "-e", "--export",
        choices=["csv", "json"],
        default=None,
        help="Export parsed records to the specified structured format.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Destination file path for export (default: output/capture.<ext>).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode: prints layer details and payload hex/ASCII dumps.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display all detected local network interfaces and exit.",
    )

    return parser.parse_args()


def main() -> int:
    """Main execution orchestrator."""
    args = parse_arguments()

    # Handle interface listing request
    if args.list_interfaces:
        print_banner()
        console.print("[bold yellow]Available Local Network Interfaces:[/bold yellow]\n")
        interfaces = get_available_interfaces()
        for idx, iface in enumerate(interfaces, start=1):
            console.print(f"  [cyan]{idx}.[/cyan] {iface}")
        return 0

    print_banner()

    stats = CaptureStatistics()
    parsed_records: List[dict] = []
    table = create_packet_table()

    # Mode 1: Offline PCAP Analysis
    if args.read_pcap:
        console.print(f"[bold cyan]► Ingesting offline PCAP file:[/bold cyan] {args.read_pcap}\n")
        try:
            raw_packets = read_pcap_file(args.read_pcap)
        except Exception as exc:
            console.print(f"[bold red]Error loading PCAP file:[/bold red] {exc}")
            return 1

        if not raw_packets:
            console.print("[yellow]Warning: Capture file contains 0 packets.[/yellow]")
            return 0

        for idx, pkt in enumerate(raw_packets, start=1):
            record = parse_packet(pkt)
            parsed_records.append(record)
            stats.update(record)

            if args.verbose:
                print_verbose_packet(idx, record)
            else:
                add_packet_row(table, idx, record)

        if not args.verbose:
            console.print(table)

    # Mode 2: Live Network Capture
    else:
        # Pre-flight environment check
        is_ready, diag_msg = check_live_capture_prerequisites()
        if not is_ready:
            console.print(f"[bold red]{diag_msg}[/bold red]")
            return 2

        console.print("[bold cyan]► Initializing live packet capture...[/bold cyan]")
        console.print(f"  Interface:  {args.interface or 'Default Adapter'}")
        console.print(f"  BPF Filter: {args.filter or 'None (All Traffic)'}")
        console.print(f"  Limit:      {args.count or 'Unlimited'} packets | Timeout: {args.timeout or 'None'}")
        console.print("[dim]Press Ctrl+C at any time to halt capture and review statistics.[/dim]\n")

        packet_index = 0

        def live_callback(pkt):
            nonlocal packet_index
            packet_index += 1
            record = parse_packet(pkt)
            parsed_records.append(record)
            stats.update(record)

            if args.verbose:
                print_verbose_packet(packet_index, record)
            else:
                add_packet_row(table, packet_index, record)

        try:
            capture_live_packets(
                interface=args.interface,
                count=args.count,
                timeout=args.timeout,
                bpf_filter=args.filter,
                packet_callback=live_callback,
                save_path=args.save_pcap,
            )
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Capture halted by operator (Ctrl+C).[/yellow]")
        except Exception as exc:
            console.print(f"\n[bold red]Capture runtime error:[/bold red] {exc}")
            return 1

        if not args.verbose and parsed_records:
            console.print(table)

    # Render summary telemetry
    if parsed_records:
        print_summary_statistics(stats)

        # Handle file exports
        if args.export:
            default_ext = args.export
            out_file = args.output or f"output/capture_export.{default_ext}"
            if args.export == "json":
                export_to_json(parsed_records, stats, out_file)
            elif args.export == "csv":
                export_to_csv(parsed_records, out_file)
    else:
        console.print("[dim]No packets processed in this session.[/dim]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
