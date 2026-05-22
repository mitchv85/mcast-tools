"""mcast-send — friendly multicast sender with live dashboard.

Usage:
    mcast-send <group> [duration_seconds] [ttl]
    mcast-send <group> --rate 25pps --ttl 100 --duration 600

Reads command-line args, sets up an IPv4 UDP socket with the appropriate
multicast options, and sends packets carrying a custom header at a steady
rate. Renders a live rich dashboard with rate, byte counts, and config.
"""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .common import (
    HEADER_SIZE,
    RouteInfo,
    classify_multicast_group,
    dscp_label,
    fmt_bps,
    fmt_bytes,
    fmt_duration,
    fmt_pps,
    is_ssm_group,
    make_packet,
    parse_dscp,
    parse_rate,
    tos_byte_from_dscp,
    validate_multicast_group,
)


DEFAULT_TTL = 100
DEFAULT_DURATION = 600  # 10 minutes
DEFAULT_RATE = "25pps"
DEFAULT_SIZE = 200
DEFAULT_DSCP = 0
SLIDING_WINDOW = 5.0  # seconds for "current rate" calculation


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcast-send",
        description=(
            "Send IPv4 multicast traffic to a group. Packets carry a custom "
            "header (orig TTL, orig DSCP, sequence, timestamp) so a paired "
            "mcast-receive can detect loss, duplicates, hop count, and DSCP "
            "remarks."
        ),
        epilog=(
            "Examples:\n"
            "  mcast-send 239.0.10.101\n"
            "  mcast-send 239.0.10.101 600 100\n"
            "  mcast-send 239.0.10.101 --rate 1Mbps --dscp ef --interface eth1\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "group",
        help="IPv4 multicast group address (e.g. 239.0.10.101)",
    )
    parser.add_argument(
        "duration",
        nargs="?",
        type=int,
        default=None,
        help=f"Duration in seconds. 0 = forever. Default: {DEFAULT_DURATION}",
    )
    parser.add_argument(
        "ttl",
        nargs="?",
        type=int,
        default=None,
        help=f"IP TTL for outgoing packets. Default: {DEFAULT_TTL}",
    )
    parser.add_argument(
        "--duration", "-t",
        dest="duration_flag",
        type=int,
        help="Same as positional duration (overrides if both given)",
    )
    parser.add_argument(
        "--ttl",
        dest="ttl_flag",
        type=int,
        help="Same as positional ttl (overrides if both given)",
    )
    parser.add_argument(
        "--rate", "-r",
        default=DEFAULT_RATE,
        help=f"Send rate (e.g. 25pps, 1Mbps). Default: {DEFAULT_RATE}",
    )
    parser.add_argument(
        "--size", "-s",
        type=int,
        default=DEFAULT_SIZE,
        help=f"Datagram size in bytes (header + payload). Default: {DEFAULT_SIZE}",
    )
    parser.add_argument(
        "--dscp",
        default=str(DEFAULT_DSCP),
        help="DSCP value (0-63 or name: be, ef, af41, cs5, etc). Default: be",
    )
    parser.add_argument(
        "--interface", "-i",
        help="Egress interface name (default: chosen by routing table)",
    )
    parser.add_argument(
        "--no-loopback",
        action="store_true",
        help="Disable IP_MULTICAST_LOOP (don't deliver to local receivers)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="No live dashboard — just print a final summary",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="On exit, print a JSON summary line (useful for automation)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcast-send {__version__}",
    )
    return parser


# ---------------------------------------------------------------------------
# Stats container
# ---------------------------------------------------------------------------

@dataclass
class SenderStats:
    started_at: float = 0.0
    packets_sent: int = 0
    bytes_sent: int = 0
    # Sliding window of (monotonic_ts, packet_count_at_ts) for current-rate calc
    rate_samples: deque = field(default_factory=lambda: deque(maxlen=2048))
    last_send_ts: float = 0.0
    errors: int = 0

    def elapsed(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.monotonic() - self.started_at

    def current_pps(self) -> float:
        """Compute pps over the trailing sliding window."""
        if len(self.rate_samples) < 2:
            return 0.0
        now = time.monotonic()
        cutoff = now - SLIDING_WINDOW
        # rate_samples is (ts, count). Walk from the left until ts >= cutoff.
        # deque doesn't support efficient slicing, so iterate.
        oldest_ts = oldest_count = None
        for ts, count in self.rate_samples:
            if ts >= cutoff:
                oldest_ts = ts
                oldest_count = count
                break
        if oldest_ts is None:
            return 0.0
        newest_ts, newest_count = self.rate_samples[-1]
        dt = newest_ts - oldest_ts
        if dt <= 0:
            return 0.0
        return (newest_count - oldest_count) / dt


# ---------------------------------------------------------------------------
# Socket setup
# ---------------------------------------------------------------------------

def setup_sender_socket(
    group: str,
    ttl: int,
    dscp: int,
    interface_ip: Optional[str],
    enable_loopback: bool,
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # TTL
    sock.setsockopt(
        socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl
    )
    # Loopback control
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_LOOP,
        1 if enable_loopback else 0,
    )
    # DSCP -> TOS byte
    if dscp != 0:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos_byte_from_dscp(dscp))
    # Egress interface override
    if interface_ip:
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(interface_ip),
        )
    return sock


def get_interface_ip(interface: str) -> Optional[str]:
    """Look up the primary IPv4 address of an interface using `ip -j addr show`."""
    import json
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "-j", "-4", "addr", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    addr_info = data[0].get("addr_info", [])
    for a in addr_info:
        if a.get("family") == "inet":
            return a.get("local")
    return None


# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------

def render_dashboard(
    group: str,
    group_class: str,
    interface: str,
    iface_ip: Optional[str],
    ttl: int,
    dscp: int,
    datagram_size: int,
    target_pps: float,
    sender_id: int,
    duration: int,
    stats: SenderStats,
    running: bool,
) -> Panel:
    cfg = Table.grid(padding=(0, 2))
    cfg.add_column(style="dim", no_wrap=True)
    cfg.add_column()

    cfg.add_row("Group:", f"[bold cyan]{group}[/]  [dim]({group_class})[/]")
    iface_str = interface if interface else "[dim]routing default[/]"
    if iface_ip:
        iface_str += f"  [dim]({iface_ip})[/]"
    cfg.add_row("Interface:", iface_str)
    cfg.add_row("TTL:", str(ttl))
    cfg.add_row("DSCP:", dscp_label(dscp))
    cfg.add_row("Datagram:", f"{datagram_size} bytes  [dim](header {HEADER_SIZE} + payload {datagram_size - HEADER_SIZE})[/]")
    cfg.add_row("Target rate:", f"{fmt_pps(target_pps)}  [dim]({fmt_bps(target_pps * datagram_size * 8)})[/]")
    cfg.add_row("Sender ID:", f"[dim]0x{sender_id:08x}[/]")

    live = Table.grid(padding=(0, 2))
    live.add_column(style="dim", no_wrap=True)
    live.add_column()

    status_dot = "[bold green]● SENDING[/]" if running else "[bold yellow]● STOPPED[/]"
    live.add_row("Status:", status_dot)
    live.add_row("Elapsed:", fmt_duration(stats.elapsed()))
    if duration > 0:
        remaining = max(0, duration - stats.elapsed())
        live.add_row("Remaining:", fmt_duration(remaining))
    else:
        live.add_row("Remaining:", "[dim]∞ (forever)[/]")
    live.add_row("Packets sent:", f"{stats.packets_sent:,}")
    live.add_row(
        "Bytes sent:",
        f"{stats.bytes_sent:,}  [dim]({fmt_bytes(stats.bytes_sent)})[/]",
    )
    pps = stats.current_pps()
    bps = pps * datagram_size * 8
    live.add_row(
        "Current rate:",
        f"{fmt_pps(pps)}  [dim]({fmt_bps(bps)})[/]",
    )
    if stats.errors:
        live.add_row("Errors:", f"[red]{stats.errors}[/]")

    body = Table.grid(padding=(0, 0))
    body.add_column()
    body.add_row(cfg)
    body.add_row(Text("─" * 60, style="dim"))
    body.add_row(live)

    return Panel(
        body,
        title="[bold]mcast-send[/]",
        subtitle="[dim]Ctrl-C to stop[/]",
        border_style="cyan",
    )


# ---------------------------------------------------------------------------
# Sender loop
# ---------------------------------------------------------------------------

def send_loop(
    sock: socket.socket,
    group: str,
    target_pps: float,
    datagram_size: int,
    ttl: int,
    dscp: int,
    sender_id: int,
    duration: int,
    stats: SenderStats,
    stop_event: threading.Event,
) -> None:
    interval = 1.0 / target_pps
    next_send = time.monotonic()
    deadline = next_send + duration if duration > 0 else float("inf")
    seq = 0
    stats.started_at = time.monotonic()

    while not stop_event.is_set():
        now = time.monotonic()
        if now >= deadline:
            break

        sleep_for = next_send - now
        if sleep_for > 0:
            # Don't oversleep past the duration deadline
            if duration > 0:
                sleep_for = min(sleep_for, deadline - now)
            # Allow stop_event to wake us
            if stop_event.wait(timeout=sleep_for):
                break
            if time.monotonic() >= deadline:
                break

        send_ns = time.monotonic_ns()
        try:
            packet = make_packet(
                seq=seq,
                send_ns=send_ns,
                sender_id=sender_id,
                orig_ttl=ttl,
                orig_dscp=dscp,
                datagram_size=datagram_size,
            )
            sock.sendto(packet, (group, 0x4D43))  # port 0x4D43 = 19779, "MC"
        except OSError as exc:
            stats.errors += 1
            # If the interface goes down etc., back off briefly
            if stop_event.wait(timeout=0.5):
                break
            _log_send_error(exc)
        else:
            stats.packets_sent += 1
            stats.bytes_sent += datagram_size
            stats.last_send_ts = time.monotonic()
            stats.rate_samples.append((stats.last_send_ts, stats.packets_sent))
            seq += 1

        next_send += interval
        # If we've fallen way behind (e.g. sleep contention), don't try to catch up
        # by firing a burst — reset the schedule.
        if next_send < time.monotonic() - 1.0:
            next_send = time.monotonic() + interval


_last_logged_err: Optional[str] = None


def _log_send_error(exc: OSError) -> None:
    """Log send errors but coalesce repeats."""
    global _last_logged_err
    msg = f"{exc.__class__.__name__}: {exc}"
    if msg != _last_logged_err:
        print(f"send error: {msg}", file=sys.stderr)
        _last_logged_err = msg


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    # ---- Validate inputs --------------------------------------------------
    try:
        group_addr = validate_multicast_group(args.group)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        return 2

    group_class = classify_multicast_group(group_addr)
    if group_addr in __import__("ipaddress").IPv4Network("224.0.0.0/24"):
        console.print(
            f"[yellow]warning:[/] {group_addr} is in 224.0.0.0/24 (link-local, "
            "not routed beyond the local link)."
        )

    duration = args.duration_flag if args.duration_flag is not None else args.duration
    if duration is None:
        duration = DEFAULT_DURATION
    if duration < 0:
        console.print("[red]error:[/] duration must be >= 0")
        return 2

    ttl = args.ttl_flag if args.ttl_flag is not None else args.ttl
    if ttl is None:
        ttl = DEFAULT_TTL
    if not 1 <= ttl <= 255:
        console.print("[red]error:[/] ttl must be 1-255")
        return 2

    if args.size < HEADER_SIZE:
        console.print(
            f"[red]error:[/] --size {args.size} too small (min {HEADER_SIZE} bytes for header)"
        )
        return 2
    if args.size > 65500:
        console.print("[red]error:[/] --size too large (max ~65500 for UDP)")
        return 2

    try:
        dscp = parse_dscp(args.dscp)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        return 2

    try:
        target_pps = parse_rate(args.rate, args.size)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        return 2

    # ---- Resolve egress interface ----------------------------------------
    iface_name = args.interface
    iface_ip: Optional[str] = None
    if iface_name:
        iface_ip = get_interface_ip(iface_name)
        if iface_ip is None:
            console.print(
                f"[yellow]warning:[/] could not resolve IPv4 address for {iface_name}"
            )
    else:
        route = RouteInfo.for_destination(str(group_addr))
        if route is not None:
            iface_name = route.interface
            iface_ip = route.src_addr

    # ---- Set up socket ----------------------------------------------------
    try:
        sock = setup_sender_socket(
            group=str(group_addr),
            ttl=ttl,
            dscp=dscp,
            interface_ip=iface_ip,
            enable_loopback=not args.no_loopback,
        )
    except OSError as e:
        console.print(f"[red]socket setup failed:[/] {e}")
        return 1

    sender_id = secrets.randbits(32)
    stats = SenderStats()
    stop_event = threading.Event()

    def handle_signal(signum, frame):
        stop_event.set()

    import signal as _signal
    _signal.signal(_signal.SIGINT, handle_signal)
    _signal.signal(_signal.SIGTERM, handle_signal)

    # Print one-time intro if quiet mode
    if args.quiet:
        console.print(
            f"mcast-send: {group_addr} via {iface_name or 'routing default'} "
            f"TTL={ttl} DSCP={dscp_label(dscp)} rate={fmt_pps(target_pps)} "
            f"size={args.size}B duration={duration}s"
        )

    # ---- Run --------------------------------------------------------------
    sender_thread = threading.Thread(
        target=send_loop,
        kwargs=dict(
            sock=sock,
            group=str(group_addr),
            target_pps=target_pps,
            datagram_size=args.size,
            ttl=ttl,
            dscp=dscp,
            sender_id=sender_id,
            duration=duration,
            stats=stats,
            stop_event=stop_event,
        ),
        daemon=True,
        name="mcast-send-tx",
    )
    sender_thread.start()

    if args.quiet:
        sender_thread.join()
    else:
        with Live(
            render_dashboard(
                group=str(group_addr),
                group_class=group_class,
                interface=iface_name or "",
                iface_ip=iface_ip,
                ttl=ttl,
                dscp=dscp,
                datagram_size=args.size,
                target_pps=target_pps,
                sender_id=sender_id,
                duration=duration,
                stats=stats,
                running=True,
            ),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            while sender_thread.is_alive():
                live.update(
                    render_dashboard(
                        group=str(group_addr),
                        group_class=group_class,
                        interface=iface_name or "",
                        iface_ip=iface_ip,
                        ttl=ttl,
                        dscp=dscp,
                        datagram_size=args.size,
                        target_pps=target_pps,
                        sender_id=sender_id,
                        duration=duration,
                        stats=stats,
                        running=True,
                    )
                )
                sender_thread.join(timeout=0.25)
            # Final frame with running=False
            live.update(
                render_dashboard(
                    group=str(group_addr),
                    group_class=group_class,
                    interface=iface_name or "",
                    iface_ip=iface_ip,
                    ttl=ttl,
                    dscp=dscp,
                    datagram_size=args.size,
                    target_pps=target_pps,
                    sender_id=sender_id,
                    duration=duration,
                    stats=stats,
                    running=False,
                )
            )

    sock.close()

    # ---- Final summary ----------------------------------------------------
    if args.json:
        import json as _json
        summary = {
            "tool": "mcast-send",
            "version": __version__,
            "group": str(group_addr),
            "interface": iface_name,
            "ttl": ttl,
            "dscp": dscp,
            "datagram_size": args.size,
            "target_pps": target_pps,
            "sender_id": f"0x{sender_id:08x}",
            "duration_requested_s": duration,
            "duration_actual_s": stats.elapsed(),
            "packets_sent": stats.packets_sent,
            "bytes_sent": stats.bytes_sent,
            "errors": stats.errors,
        }
        print(_json.dumps(summary))
    elif args.quiet:
        console.print(
            f"sent {stats.packets_sent:,} packets / {fmt_bytes(stats.bytes_sent)} "
            f"in {fmt_duration(stats.elapsed())} (errors: {stats.errors})"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
