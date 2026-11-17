"""Terminal Presentation and File Export Formatting Module.

File: analyzer/formatter.py
Purpose: Renders packet inspection records and summary metrics into color-coded Rich tables,
verbose forensic views, and standard export formats (JSON, CSV).
How it fits: Consumes parsed packet records from parser.py and stats from stats.py to
produce human and machine-readable output.
Author: CodSoft Cyber Security Intern
How to run: Automatically called by packet_analyzer.py.

LEARNING NOTE:
Security operations rely heavily on both real-time visual feeds (for triage) and
structured machine exports (CSV/JSON for SIEM ingestion and forensic pipelines).
Color coding protocols (e.g., TCP in blue, UDP in green, ICMP in yellow) enables rapid
visual scanning during active incidents.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from analyzer.stats import CaptureStatistics

# Terminal console instance
console = Console()

# Protocol color coding palette for terminal output
PROTOCOL_COLORS: Dict[str, str] = {
    "TCP": "bold cyan",
    "UDP": "bold green",
    "ICMP": "bold yellow",
    "ARP": "bold magenta",
    "DNS": "bold bright_blue",
    "OTHER": "dim white",
}


def get_protocol_style(proto: str) -> str:
    """Return the Rich styling string assigned to a protocol."""
    return PROTOCOL_COLORS.get(proto, "white")


def print_banner() -> None:
    """Display startup banner with legal, authorized-use-only ethics notification."""
    banner_text = (
        "[bold cyan]╔══════════════════════════════════════════════════════════════════════╗[/bold cyan]\n"
        "[bold cyan]║[/bold cyan]            [bold white]CodSoft Cyber Security: Network Packet Analyzer[/bold white]           [bold cyan]║[/bold cyan]\n"
        "[bold cyan]╚══════════════════════════════════════════════════════════════════════╝[/bold cyan]\n"
        "[bold red]► ETHICS & LEGAL NOTICE:[/bold red] [yellow]This tool is intended strictly for authorized educational[/yellow]\n"
        "[yellow]  network analysis, diagnostic inspection, and security defense research.[/yellow]\n"
        "[yellow]  Do NOT capture traffic on networks without explicit, documented permission.[/yellow]"
    )
    console.print(Panel(banner_text, border_style="cyan"))


def create_packet_table() -> Table:
    """Create a formatted Rich table structure for live or batch packet streaming."""
    table = Table(
        title="[bold white]Captured Network Packets[/bold white]",
        header_style="bold bright_white on dark_blue",
        show_lines=False,
    )
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Timestamp", style="cyan", width=20)
    table.add_column("Proto", width=7, justify="center")
    table.add_column("Source Address", width=21)
    table.add_column("Destination Address", width=21)
    table.add_column("Port/Service", width=16)
    table.add_column("Flags / Info", style="white")
    table.add_column("Len", style="green", width=6, justify="right")
    return table


def add_packet_row(table: Table, index: int, record: Dict[str, Any]) -> None:
    """Format and append a single packet record as a row in the Rich table.

    Args:
        table: Target Rich Table instance.
        index: Sequential 1-based packet index.
        record: Normalized packet dictionary from analyzer.parser.
    """
    proto = record.get("protocol", "OTHER")
    proto_style = get_protocol_style(proto)
    proto_cell = f"[{proto_style}]{proto}[/{proto_style}]"

    # Format endpoints
    src = str(record.get("src_ip", "N/A"))
    dst = str(record.get("dst_ip", "N/A"))

    # Service / Port resolution
    src_p = record.get("src_port")
    dst_p = record.get("dst_port")
    srv = record.get("service")

    if src_p is not None and dst_p is not None:
        port_info = f"{src_p} -> {dst_p}"
        if srv:
            port_info += f" ({srv})"
    else:
        port_info = "-"

    # TCP Flags or Application hint
    info_parts = []
    flags = record.get("tcp_flags", [])
    if flags:
        info_parts.append(f"[{','.join(flags)}]")
    if record.get("app_hint"):
        info_parts.append(record["app_hint"])
    info_str = " ".join(info_parts) if info_parts else "-"

    table.add_row(
        str(index),
        record.get("timestamp", ""),
        proto_cell,
        src,
        dst,
        port_info,
        info_str,
        f"{record.get('length', 0)}B",
    )


def print_verbose_packet(index: int, record: Dict[str, Any]) -> None:
    """Print complete packet attributes, layer headers, and payload hex dump.

    Args:
        index: Packet sequence number.
        record: Packet record dictionary.
    """
    proto = record.get("protocol", "OTHER")
    style = get_protocol_style(proto)
    console.print(f"\n[bold underline {style}]=== Packet #{index} [{proto}] ===[/bold underline {style}]")
    console.print(f"  [bold]Timestamp:[/bold]      {record.get('timestamp')}")
    console.print(f"  [bold]Total Length:[/bold]   {record.get('length')} bytes | TTL: {record.get('ttl', 'N/A')}")
    console.print(f"  [bold]Source:[/bold]         {record.get('src_ip')}:{record.get('src_port') or '-'}")
    console.print(f"  [bold]Destination:[/bold]    {record.get('dst_ip')}:{record.get('dst_port') or '-'}")
    if record.get("service"):
        console.print(f"  [bold]Service:[/bold]        {record.get('service')}")
    if record.get("tcp_flags"):
        console.print(f"  [bold]TCP Flags:[/bold]      {', '.join(record['tcp_flags'])}")
    if record.get("app_hint"):
        console.print(f"  [bold]App Layer:[/bold]      [yellow]{record['app_hint']}[/yellow]")
    console.print(f"  [bold]Payload Length:[/bold] {record.get('payload_len')} bytes")
    console.print(f"  [bold]Payload Preview:[/bold]\n[dim]{record.get('payload_preview')}[/dim]")


def print_summary_statistics(stats: CaptureStatistics) -> None:
    """Render terminal summary table including protocol breakdowns and top talkers.

    Args:
        stats: Populated CaptureStatistics instance.
    """
    summary_data = stats.to_dict()

    summary_table = Table(title="[bold yellow]Capture Session Summary[/bold yellow]", border_style="yellow")
    summary_table.add_column("Metric", style="bold white", width=25)
    summary_table.add_column("Value", style="cyan")

    summary_table.add_row("Total Packets Captured", str(summary_data["total_packets"]))
    summary_table.add_row("Total Data Volume", f"{summary_data['total_bytes']:,} bytes")
    summary_table.add_row("Capture Duration", f"{summary_data['duration_seconds']} seconds")
    summary_table.add_row("Average Throughput", f"{summary_data['packets_per_second']} pkts/sec")

    # Protocol breakdown
    proto_lines = [
        f"{proto}: {count} ({round((count / summary_data['total_packets']) * 100, 1)}%)"
        for proto, count in summary_data["protocol_breakdown"].items()
    ]
    summary_table.add_row("Protocol Breakdown", "\n".join(proto_lines) if proto_lines else "None")

    # Top talkers
    talker_lines = [f"{item['ip']} ({item['count']} pkts)" for item in summary_data["top_source_ips"]]
    summary_table.add_row("Top Source IPs (Talkers)", "\n".join(talker_lines) if talker_lines else "None")

    # Top destination ports
    port_lines = [
        f"Port {item['port']} [{item['service']}]: {item['count']} pkts"
        for item in summary_data["top_destination_ports"]
    ]
    summary_table.add_row("Top Destination Ports", "\n".join(port_lines) if port_lines else "None")

    console.print("\n")
    console.print(summary_table)


def export_to_json(records: List[Dict[str, Any]], stats: CaptureStatistics, filepath: str) -> None:
    """Export packet records and session statistics to a formatted JSON document.

    Args:
        records: List of parsed packet records.
        stats: CaptureStatistics instance.
        filepath: Output filesystem path.
    """
    out_path = Path(filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "generator": "CodSoft Network Packet Analyzer",
            "version": "1.0.0",
        },
        "summary": stats.to_dict(),
        "packets": records,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    console.print(f"[bold green]✔ Successfully exported {len(records)} packets to JSON:[/bold green] {out_path}")


def export_to_csv(records: List[Dict[str, Any]], filepath: str) -> None:
    """Export packet records to a tabular CSV file for spreadsheet analysis.

    Args:
        records: List of parsed packet records.
        filepath: Output filesystem path.
    """
    out_path = Path(filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "service",
        "length",
        "ttl",
        "tcp_flags",
        "app_hint",
        "payload_len",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            # Flatten lists to comma strings
            flat_rec = dict(rec)
            flat_rec["tcp_flags"] = ",".join(flat_rec.get("tcp_flags", []))
            writer.writerow(flat_rec)
    console.print(f"[bold green]✔ Successfully exported {len(records)} packets to CSV:[/bold green] {out_path}")
