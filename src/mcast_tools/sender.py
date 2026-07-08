"""mcast-send — friendly multicast sender with live dashboard.

Usage:
    mcast-send <group> [duration_seconds] [ttl]
    mcast-send <group> --rate 25pps --ttl 100 --duration 600
    mcast-send ff3e::8000:1 --rate 1Mbps --dscp ef --interface eth1

Reads command-line args, sets up a UDP socket of the group's address
family (IPv4 or IPv6) with the appropriate multicast options, and sends
packets carrying a custom header at a steady rate. Renders a live rich
dashboard with rate, byte counts, and config.
"""
from __future__ import annotations

import argparse
import errno
import ipaddress
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
    needs_explicit_interface,
    parse_dscp,
    parse_rate,
    split_scope,
    tos_byte_from_dscp,
    validate_multicast_group,
    validate_source,
)


DEFAULT_TTL = 100
DEFAULT_DURATION = 600  # 10 minutes
DEFAULT_RATE = "25pps"
DEFAULT_SIZE = 200
DEFAULT_DSCP = 0
SLIDING_WINDOW = 5.0  # seconds for "current rate" calculation
MCAST_PORT = 0x4D43  # 19779, "MC" — matches receiver

# IPv6 traffic class — same DSCP layout as the v4 TOS byte. getattr in case
# an exotic Python build doesn't expose it (Linux value: 67).
IPV6_TCLASS = getattr(socket, "IPV6_TCLASS", 67)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcast-send",
        description=(
            "Send IPv4 or IPv6 multicast traffic to a group. Packets carry a "
            "custom header (orig TTL/hop limit, orig DSCP, sequence, "
            "timestamp) so a paired mcast-receive can detect loss, "
            "duplicates, hop count, and DSCP remarks."
        ),
        epilog=(
            "Examples:\n"
            "  mcast-send 239.0.10.101\n"
            "  mcast-send 239.0.10.101 600 100\n"
            "  mcast-send 239.0.10.101 --rate 1Mbps --dscp ef --interface eth1\n"
            "  mcast-send ff3e::8000:1 --rate 1Mbps --dscp ef --interface eth1\n"
            "  mcast-send ff02::42%eth1     (link-local scope — zone names the interface)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "group",
        help=(
            "Multicast group address — IPv4 (e.g. 239.0.10.101) or IPv6 "
            "(e.g. ff3e::8000:1; link-local groups may carry a %%zone like "
            "ff02::42%%eth1)"
        ),
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
        help=(
            f"IPv4 TTL / IPv6 hop limit for outgoing packets. "
            f"Default: {DEFAULT_TTL}"
        ),
    )
    parser.add_argument(
        "--duration", "-t",
        dest="duration_flag",
        type=int,
        help="Same as positional duration (overrides if both given)",
    )
    parser.add_argument(
        "--ttl", "--hop-limit",
        dest="ttl_flag",
        type=int,
        help=(
            "Same as positional ttl (overrides if both given). "
            "--hop-limit is the IPv6-flavored alias."
        ),
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
        "--source", "-S",
        help=(
            "Source address to send FROM (binds the socket). Without this, "
            "the kernel picks via source-address selection (RFC 6724 on "
            "IPv6) — which is non-deterministic when an interface carries "
            "multiple candidate addresses. Pin it for SSM demos. Pair with "
            "--interface for fully deterministic egress."
        ),
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
    # Guards rate_samples: the worker thread appends while the dashboard
    # thread reads — ANY deque mutation invalidates live iterators.
    _rate_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )
    last_send_ts: float = 0.0
    errors: int = 0

    def elapsed(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.monotonic() - self.started_at

    def record_rate_sample(self, ts: float, count: int) -> None:
        """Worker-thread side: append a (ts, count) sample under the lock."""
        with self._rate_lock:
            self.rate_samples.append((ts, count))

    def current_pps(self) -> float:
        """Compute pps over the trailing sliding window.

        Snapshot-then-compute: the lock is held only for the copy, and the
        walk happens on an immutable tuple the worker can't touch.
        """
        with self._rate_lock:
            samples = tuple(self.rate_samples)
        if len(samples) < 2:
            return 0.0
        now = time.monotonic()
        cutoff = now - SLIDING_WINDOW
        # samples is (ts, count). Walk from the left until ts >= cutoff.
        oldest_ts = oldest_count = None
        for ts, count in samples:
            if ts >= cutoff:
                oldest_ts = ts
                oldest_count = count
                break
        if oldest_ts is None:
            return 0.0
        newest_ts, newest_count = samples[-1]
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
    source: Optional[str] = None,
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
    # Pin the source address. Note this sets the *source*, not the egress —
    # IP_MULTICAST_IF (or the route table) still decides the interface.
    if source:
        sock.bind((source, 0))
    return sock


def setup_sender_socket_v6(
    hops: int,
    dscp: int,
    ifindex: Optional[int],
    enable_loopback: bool,
    source: Optional[str] = None,
) -> socket.socket:
    """IPv6 sibling of setup_sender_socket. Key differences from v4:
    hop limit instead of TTL, traffic class instead of TOS, and
    IPV6_MULTICAST_IF takes an interface *index*, not an address."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, hops)
    sock.setsockopt(
        socket.IPPROTO_IPV6,
        socket.IPV6_MULTICAST_LOOP,
        1 if enable_loopback else 0,
    )
    # DSCP -> traffic class byte (same layout as the v4 TOS byte)
    if dscp != 0:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_TCLASS, tos_byte_from_dscp(dscp))
    # Egress interface override — by index for IPv6
    if ifindex:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    # Pin the source address — takes RFC 6724 selection out of the picture
    # entirely (the rules only apply to unbound sockets). Sources are
    # validated zone-free upstream, so scope_id 0 is correct here.
    if source:
        sock.bind((source, 0, 0, 0))
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


def _pick_v6_addr(addr_info: list) -> Optional[str]:
    """Pick a display address from `ip -j -6 addr show` addr_info entries.

    Prefers global scope (stable, routable) over link scope; ignores any
    non-inet6 entries defensively.
    """
    link_fallback: Optional[str] = None
    for a in addr_info:
        if a.get("family") != "inet6":
            continue
        if a.get("scope") == "global":
            return a.get("local")
        if a.get("scope") == "link" and link_fallback is None:
            link_fallback = a.get("local")
    return link_fallback


def get_interface_ipv6(interface: str) -> Optional[str]:
    """Look up an IPv6 address of an interface (global preferred, link
    fallback) using `ip -j -6 addr show`."""
    import json
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "-j", "-6", "addr", "show", "dev", interface],
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
    return _pick_v6_addr(data[0].get("addr_info", []))


def make_send_dest(
    group_addr: "ipaddress.IPv4Address | ipaddress.IPv6Address",
    port: int,
    ifindex: Optional[int],
) -> tuple:
    """Build the family-appropriate sendto destination.

    IPv4 → (host, port). IPv6 → (host, port, flowinfo, scope_id); any
    %zone on the group rides in the scope_id slot, never the host string.
    """
    if isinstance(group_addr, ipaddress.IPv6Address):
        unscoped, _zone = split_scope(group_addr)
        return (str(unscoped), port, 0, ifindex or 0)
    return (str(group_addr), port)


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
    hop_label: str = "TTL",
    source: Optional[str] = None,
) -> Panel:
    cfg = Table.grid(padding=(0, 2))
    cfg.add_column(style="dim", no_wrap=True)
    cfg.add_column()

    cfg.add_row("Group:", f"[bold cyan]{group}[/]  [dim]({group_class})[/]")
    if source:
        cfg.add_row("Source:", f"{source}  [dim](bound)[/]")
    iface_str = interface if interface else "[dim]routing default[/]"
    if iface_ip:
        iface_str += f"  [dim]({iface_ip})[/]"
    cfg.add_row("Interface:", iface_str)
    cfg.add_row(f"{hop_label}:", str(ttl))
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
    dest: tuple,
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
            sock.sendto(packet, dest)  # port 0x4D43 = 19779, "MC"
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
            stats.record_rate_sample(stats.last_send_ts, stats.packets_sent)
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
    is_v6 = isinstance(group_addr, ipaddress.IPv6Address)
    hop_label = "Hop limit" if is_v6 else "TTL"

    source_ip: Optional[str] = None
    if args.source:
        try:
            source_ip = str(validate_source(args.source, group_addr))
        except ValueError as e:
            console.print(f"[red]error:[/] {e}")
            return 2
    if not is_v6 and group_addr in ipaddress.IPv4Network("224.0.0.0/24"):
        console.print(
            f"[yellow]warning:[/] {group_addr} is in 224.0.0.0/24 (link-local, "
            "not routed beyond the local link)."
        )
    if is_v6 and needs_explicit_interface(group_addr):
        console.print(
            f"[yellow]warning:[/] {group_addr} is interface-/link-local scope "
            "(not routed beyond the local link)."
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
        console.print(f"[red]error:[/] {hop_label.lower()} must be 1-255")
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
    ifindex: Optional[int] = None
    group_host = str(group_addr)

    if is_v6:
        unscoped, zone = split_scope(group_addr)
        group_host = str(unscoped)
        if zone and iface_name and zone != iface_name:
            console.print(
                f"[red]error:[/] group zone %{zone} conflicts with "
                f"--interface {iface_name} — pick one"
            )
            return 2
        iface_name = iface_name or zone
        if iface_name:
            try:
                ifindex = socket.if_nametoindex(iface_name)
            except OSError:
                console.print(
                    f"[red]error:[/] interface '{iface_name}' not found"
                )
                return 2
            iface_ip = get_interface_ipv6(iface_name)
            if iface_ip is None:
                console.print(
                    f"[yellow]warning:[/] could not resolve an IPv6 address "
                    f"for {iface_name}"
                )
        else:
            route = RouteInfo.for_destination(group_host)
            if route is not None:
                iface_name = route.interface
                iface_ip = route.src_addr
                try:
                    ifindex = socket.if_nametoindex(iface_name)
                except OSError:
                    ifindex = None
        if needs_explicit_interface(group_addr) and not ifindex:
            console.print(
                f"[red]error:[/] {group_host} is interface-/link-local scope — "
                "the kernel needs an interface. Use a %zone "
                f"({group_host}%eth1) or --interface."
            )
            return 2
    else:
        if iface_name:
            iface_ip = get_interface_ip(iface_name)
            if iface_ip is None:
                console.print(
                    f"[yellow]warning:[/] could not resolve IPv4 address for {iface_name}"
                )
        else:
            route = RouteInfo.for_destination(group_host)
            if route is not None:
                iface_name = route.interface
                iface_ip = route.src_addr

    # ---- Set up socket ----------------------------------------------------
    try:
        if is_v6:
            sock = setup_sender_socket_v6(
                hops=ttl,
                dscp=dscp,
                ifindex=ifindex,
                enable_loopback=not args.no_loopback,
                source=source_ip,
            )
        else:
            sock = setup_sender_socket(
                group=group_host,
                ttl=ttl,
                dscp=dscp,
                interface_ip=iface_ip,
                enable_loopback=not args.no_loopback,
                source=source_ip,
            )
    except OSError as e:
        if source_ip and e.errno == errno.EADDRNOTAVAIL:
            console.print(
                f"[red]error:[/] source {source_ip} isn't assigned to this "
                f"host. Check `ip {'-6 ' if is_v6 else ''}addr` and pick an "
                "address that exists (ideally on the egress interface)."
            )
            return 1
        console.print(f"[red]socket setup failed:[/] {e}")
        return 1

    dest = make_send_dest(group_addr, MCAST_PORT, ifindex)

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
            f"mcast-send: {group_host} via {iface_name or 'routing default'} "
            + (f"src={source_ip} " if source_ip else "")
            + f"{hop_label}={ttl} DSCP={dscp_label(dscp)} rate={fmt_pps(target_pps)} "
            f"size={args.size}B duration={duration}s"
        )

    # ---- Run --------------------------------------------------------------
    sender_thread = threading.Thread(
        target=send_loop,
        kwargs=dict(
            sock=sock,
            dest=dest,
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
                group=group_host,
                group_class=group_class,
                hop_label=hop_label,
                interface=iface_name or "",
                iface_ip=iface_ip,
                ttl=ttl,
                dscp=dscp,
                datagram_size=args.size,
                target_pps=target_pps,
                sender_id=sender_id,
                duration=duration,
                stats=stats,
                source=source_ip,
                running=True,
            ),
            console=console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            while sender_thread.is_alive():
                live.update(
                    render_dashboard(
                        group=group_host,
                        group_class=group_class,
                        hop_label=hop_label,
                        interface=iface_name or "",
                        iface_ip=iface_ip,
                        ttl=ttl,
                        dscp=dscp,
                        datagram_size=args.size,
                        target_pps=target_pps,
                        sender_id=sender_id,
                        duration=duration,
                        stats=stats,
                        source=source_ip,
                        running=True,
                    )
                )
                sender_thread.join(timeout=0.25)
            # Final frame with running=False
            live.update(
                render_dashboard(
                    group=group_host,
                    group_class=group_class,
                    hop_label=hop_label,
                    interface=iface_name or "",
                    iface_ip=iface_ip,
                    ttl=ttl,
                    dscp=dscp,
                    datagram_size=args.size,
                    target_pps=target_pps,
                    sender_id=sender_id,
                    duration=duration,
                    stats=stats,
                    source=source_ip,
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
            "group": group_host,
            "family": group_addr.version,
            "source": source_ip,
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
