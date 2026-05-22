"""mcast-receive — friendly multicast receiver with live dashboard.

Joins a multicast group (ASM or SSM), optionally forces IGMP version,
and renders a live rich dashboard showing:
- Join interface and IGMP version (forced and observed)
- Receive status (RECEIVING / STALLED) and last-packet age
- Current pps and total counts
- Received TTL vs sender-stamped original TTL (hop count!)
- Received DSCP vs sender-stamped original DSCP (remark detection!)
- Loss / duplicate / reorder counters via embedded sequence numbers
- Sender restart detection via embedded sender_id

Usage:
    mcast-receive <group>
    mcast-receive <group> --source <source_ip>
    mcast-receive 239.0.10.101 --source 10.1.1.1 --igmp-version 3
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
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
    PacketHeader,
    RouteInfo,
    classify_multicast_group,
    dscp_from_tos_byte,
    dscp_label,
    fmt_bytes,
    fmt_duration,
    fmt_pps,
    get_interface_igmp_version,
    is_ssm_group,
    parse_proc_net_igmp,
    read_force_igmp_version,
    require_root_or_warn,
    validate_multicast_group,
    validate_source,
    write_force_igmp_version,
)


# ---------------------------------------------------------------------------
# Linux socket constants not exposed by Python's socket module on every version
# ---------------------------------------------------------------------------

IP_RECVTTL = getattr(socket, "IP_RECVTTL", 12)
IP_RECVTOS = getattr(socket, "IP_RECVTOS", 13)
IP_MULTICAST_ALL = getattr(socket, "IP_MULTICAST_ALL", 49)
# cmsg_type for received TTL/TOS — note these are the *unprefixed* IP_TTL/IP_TOS
CMSG_IP_TTL = 2
CMSG_IP_TOS = 1

MCAST_PORT = 0x4D43  # 19779, matches sender
DEFAULT_STALL_TIMEOUT = 3.0  # seconds
DEFAULT_IGMP_VERSION = 3
SLIDING_WINDOW = 5.0
RECV_BUF_BYTES = 65535


# ---------------------------------------------------------------------------
# Stats container
# ---------------------------------------------------------------------------

@dataclass
class SenderTrack:
    """Per-sender state for sequence tracking."""
    first_seen_seq: int = 0
    expected_seq: int = 0
    highest_seq_seen: int = -1
    packets: int = 0
    seen_seqs_recent: deque = field(default_factory=lambda: deque(maxlen=4096))
    seen_seqs_set: set = field(default_factory=set)


@dataclass
class GapEvent:
    """A stall-and-resume event we can display in the dashboard log."""
    started_at: float
    ended_at: Optional[float]
    packets_missed: int = 0

    def duration(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.monotonic()
        return end - self.started_at


@dataclass
class ReceiverStats:
    started_at: float = 0.0
    packets_recv: int = 0
    bytes_recv: int = 0
    foreign_packets: int = 0  # packets for our group that didn't match our header
    last_recv_ts: float = 0.0
    last_recv_ttl: Optional[int] = None
    last_recv_dscp: Optional[int] = None
    last_orig_ttl: Optional[int] = None
    last_orig_dscp: Optional[int] = None
    last_src_addr: Optional[str] = None

    # Per-sender tracking for accurate seq accounting
    senders: dict[int, SenderTrack] = field(default_factory=dict)
    sender_restarts: int = 0

    # Aggregated quality counters
    gaps: int = 0
    packets_lost_total: int = 0
    duplicates: int = 0
    reordered: int = 0

    # Stall log (most recent first, capped)
    gap_events: deque = field(default_factory=lambda: deque(maxlen=10))
    currently_stalled: bool = False
    current_gap: Optional[GapEvent] = None

    rate_samples: deque = field(default_factory=lambda: deque(maxlen=2048))

    def elapsed(self) -> float:
        if self.started_at == 0:
            return 0.0
        return time.monotonic() - self.started_at

    def time_since_last_packet(self) -> Optional[float]:
        if self.last_recv_ts == 0:
            return None
        return time.monotonic() - self.last_recv_ts

    def current_pps(self) -> float:
        if len(self.rate_samples) < 2:
            return 0.0
        now = time.monotonic()
        cutoff = now - SLIDING_WINDOW
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
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcast-receive",
        description=(
            "Join an IPv4 multicast group and report reception in real time. "
            "Detects sender-stamped original TTL/DSCP for hop count and "
            "remark visibility. Detects loss, duplicates, reordering, gaps, "
            "and sender restarts via embedded sequence/ID metadata."
        ),
        epilog=(
            "Examples:\n"
            "  mcast-receive 239.0.10.101\n"
            "  mcast-receive 239.0.10.101 --source 10.1.1.1\n"
            "  mcast-receive 232.5.5.5 --source 10.1.1.1 --igmp-version 3\n"
            "  mcast-receive 239.0.10.101 --igmp-version 2 --interface eth1\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("group", help="IPv4 multicast group address")
    parser.add_argument(
        "source",
        nargs="?",
        default=None,
        help="Source IP for SSM (S,G) join. Optional.",
    )
    parser.add_argument(
        "igmp_version",
        nargs="?",
        type=int,
        default=None,
        choices=[1, 2, 3],
        help=f"IGMP version (1/2/3). Default: {DEFAULT_IGMP_VERSION}",
    )
    parser.add_argument(
        "--source", "-S",
        dest="source_flag",
        help="Same as positional source (flag form)",
    )
    parser.add_argument(
        "--igmp-version", "-v",
        dest="igmp_version_flag",
        type=int,
        choices=[1, 2, 3],
        help="Same as positional igmp_version (flag form)",
    )
    parser.add_argument(
        "--interface", "-i",
        help="Interface to join on (default: chosen by routing table)",
    )
    parser.add_argument(
        "--stall-timeout",
        type=float,
        default=DEFAULT_STALL_TIMEOUT,
        help=f"Seconds without a packet before marking STALLED. Default: {DEFAULT_STALL_TIMEOUT}",
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
        "--duration", "-t",
        type=int,
        default=0,
        help="Auto-stop after N seconds. 0 = run until Ctrl-C (default)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcast-receive {__version__}",
    )
    return parser


# ---------------------------------------------------------------------------
# Socket setup and multicast joins
# ---------------------------------------------------------------------------

def setup_receiver_socket(
    group: str,
    source: Optional[str],
    interface_ip: Optional[str],
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass

    # Don't deliver multicast traffic for groups we haven't explicitly joined
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
    except OSError:
        pass

    # Enable per-packet TTL and TOS in ancillary data
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVTOS, 1)
    except OSError:
        pass

    # Bind to the multicast address + port. Binding to the group address rather
    # than INADDR_ANY makes the kernel filter by destination IP for us, so we
    # only receive traffic destined to this exact group.
    sock.bind((group, MCAST_PORT))

    # Determine the interface address to use for the join.
    iface_addr = interface_ip if interface_ip else "0.0.0.0"

    if source:
        # SSM: source-specific join — IP_ADD_SOURCE_MEMBERSHIP
        # struct ip_mreq_source { in_addr multi; in_addr iface; in_addr source; }
        mreq = struct.pack(
            "=4s4s4s",
            socket.inet_aton(group),
            socket.inet_aton(iface_addr),
            socket.inet_aton(source),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_SOURCE_MEMBERSHIP, mreq)
    else:
        # ASM: any-source join — IP_ADD_MEMBERSHIP
        mreq = struct.pack(
            "=4s4s",
            socket.inet_aton(group),
            socket.inet_aton(iface_addr),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    return sock


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def process_packet(
    data: bytes,
    src_addr: tuple,
    recv_ttl: Optional[int],
    recv_tos: Optional[int],
    stats: ReceiverStats,
    stall_timeout: float,
) -> None:
    """Decode a received packet and update stats."""
    hdr = PacketHeader.decode(data)
    if hdr is None:
        # Foreign packet — doesn't match our header. Common when other
        # tools (iperf, ffmpeg, etc.) are also using the group.
        stats.foreign_packets += 1
        return

    now = time.monotonic()
    src_ip = src_addr[0] if src_addr else None

    # Sender tracking
    track = stats.senders.get(hdr.sender_id)
    if track is None:
        if stats.senders:
            # Not the first sender we've seen — this might be a restart or a
            # truly new sender. We'll bump the restart counter on first packet
            # from a new sender_id (a clean restart looks like a new sender_id
            # because we randomize per invocation).
            stats.sender_restarts += 1
        track = SenderTrack(
            first_seen_seq=hdr.seq,
            expected_seq=hdr.seq + 1,
            highest_seq_seen=hdr.seq,
            packets=1,
        )
        track.seen_seqs_recent.append(hdr.seq)
        track.seen_seqs_set.add(hdr.seq)
        stats.senders[hdr.sender_id] = track
    else:
        if hdr.seq in track.seen_seqs_set:
            stats.duplicates += 1
        else:
            track.seen_seqs_recent.append(hdr.seq)
            track.seen_seqs_set.add(hdr.seq)
            # Trim seen set as deque rotates
            while len(track.seen_seqs_set) > track.seen_seqs_recent.maxlen:
                # Pop oldest from set when it rotates out of the deque
                # (we can't peek what fell off the deque cheaply, so check
                # if the set has grown past the deque)
                # Rebuild the set occasionally — cheap given maxlen 4096.
                track.seen_seqs_set = set(track.seen_seqs_recent)
                break

            if hdr.seq < track.highest_seq_seen:
                stats.reordered += 1
            elif hdr.seq > track.expected_seq:
                # We jumped forward — packets in between are missing
                missing = hdr.seq - track.expected_seq
                stats.packets_lost_total += missing

            if hdr.seq > track.highest_seq_seen:
                track.highest_seq_seen = hdr.seq
                track.expected_seq = hdr.seq + 1
        track.packets += 1

    # Stall tracking
    if stats.last_recv_ts != 0:
        gap = now - stats.last_recv_ts
        if gap >= stall_timeout and not stats.currently_stalled:
            # We missed the transition because we got a packet — but the gap
            # was long enough to count as one. Close any open gap.
            pass
    if stats.currently_stalled:
        if stats.current_gap is not None:
            stats.current_gap.ended_at = now
            # Estimate packets missed via highest_seq jump from this sender
            # if available
            if track is not None and stats.last_recv_ts != 0:
                # Approximate: missed = bumped lost count since gap started
                pass
        stats.currently_stalled = False
        stats.current_gap = None

    # Update top-level stats
    stats.packets_recv += 1
    stats.bytes_recv += len(data)
    stats.last_recv_ts = now
    stats.last_recv_ttl = recv_ttl
    stats.last_orig_ttl = hdr.orig_ttl
    stats.last_orig_dscp = hdr.orig_dscp
    stats.last_src_addr = src_ip
    if recv_tos is not None:
        stats.last_recv_dscp = dscp_from_tos_byte(recv_tos)
    stats.rate_samples.append((now, stats.packets_recv))


def check_stall(stats: ReceiverStats, stall_timeout: float) -> None:
    """Run periodically to detect stalls and open a gap event."""
    if stats.last_recv_ts == 0:
        return
    gap = time.monotonic() - stats.last_recv_ts
    if gap >= stall_timeout and not stats.currently_stalled:
        stats.currently_stalled = True
        stats.gaps += 1
        stats.current_gap = GapEvent(started_at=stats.last_recv_ts, ended_at=None)
        stats.gap_events.appendleft(stats.current_gap)


# ---------------------------------------------------------------------------
# Receive loop
# ---------------------------------------------------------------------------

def recv_loop(
    sock: socket.socket,
    stats: ReceiverStats,
    stop_event: threading.Event,
    stall_timeout: float,
    duration: int,
) -> None:
    stats.started_at = time.monotonic()
    deadline = stats.started_at + duration if duration > 0 else float("inf")
    sock.settimeout(0.25)

    while not stop_event.is_set():
        if time.monotonic() >= deadline:
            break
        try:
            data, ancdata, _flags, src_addr = sock.recvmsg(
                RECV_BUF_BYTES, socket.CMSG_SPACE(64)
            )
        except socket.timeout:
            check_stall(stats, stall_timeout)
            continue
        except OSError:
            check_stall(stats, stall_timeout)
            continue

        recv_ttl: Optional[int] = None
        recv_tos: Optional[int] = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level != socket.IPPROTO_IP:
                continue
            if cmsg_type == CMSG_IP_TTL and len(cmsg_data) >= 4:
                recv_ttl = struct.unpack("=i", cmsg_data[:4])[0]
            elif cmsg_type == CMSG_IP_TOS and len(cmsg_data) >= 1:
                recv_tos = cmsg_data[0]

        process_packet(data, src_addr, recv_ttl, recv_tos, stats, stall_timeout)
        check_stall(stats, stall_timeout)


# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------

def render_dashboard(
    group: str,
    group_class: str,
    source: Optional[str],
    join_type: str,
    interface: str,
    iface_ip: Optional[str],
    requested_igmp: int,
    observed_igmp: Optional[str],
    stats: ReceiverStats,
    stall_timeout: float,
    running: bool,
) -> Panel:
    cfg = Table.grid(padding=(0, 2))
    cfg.add_column(style="dim", no_wrap=True)
    cfg.add_column()

    cfg.add_row("Group:", f"[bold cyan]{group}[/]  [dim]({group_class})[/]")
    if source:
        cfg.add_row("Source:", f"[bold]{source}[/]")
    else:
        cfg.add_row("Source:", "[dim](any)[/]")
    cfg.add_row("Join type:", join_type)
    iface_str = interface if interface else "[dim]routing default[/]"
    if iface_ip:
        iface_str += f"  [dim]({iface_ip})[/]"
    cfg.add_row("Interface:", iface_str)

    # IGMP version row — show requested vs observed
    if observed_igmp:
        obs_int = int(observed_igmp.lstrip("V")) if observed_igmp.startswith("V") else None
        if obs_int == requested_igmp:
            igmp_str = f"v{requested_igmp} (forced)  [green]✓ confirmed[/]"
        else:
            igmp_str = (
                f"v{requested_igmp} requested, [yellow]operating as {observed_igmp}[/]"
            )
    else:
        igmp_str = f"v{requested_igmp} requested  [dim](observed: unknown)[/]"
    cfg.add_row("IGMP version:", igmp_str)

    # ----- live section -----
    live = Table.grid(padding=(0, 2))
    live.add_column(style="dim", no_wrap=True)
    live.add_column()

    # Status
    age = stats.time_since_last_packet()
    if stats.packets_recv == 0:
        status = "[bold yellow]● WAITING[/] [dim](no packets yet)[/]"
    elif stats.currently_stalled:
        status = (
            f"[bold red]● STALLED[/]  [dim]({age:.1f}s since last packet)[/]"
        )
    elif age is not None and age >= stall_timeout / 2:
        status = (
            f"[bold yellow]● RECEIVING[/] [dim](last: {age:.1f}s ago)[/]"
        )
    else:
        status = "[bold green]● RECEIVING[/]"
    live.add_row("Status:", status)

    live.add_row("Elapsed:", fmt_duration(stats.elapsed()))
    if age is not None:
        live.add_row("Last packet:", f"{age:.2f}s ago")
    live.add_row("Packets recv:", f"{stats.packets_recv:,}")
    live.add_row(
        "Bytes recv:",
        f"{stats.bytes_recv:,}  [dim]({fmt_bytes(stats.bytes_recv)})[/]",
    )
    live.add_row("Current rate:", fmt_pps(stats.current_pps()))
    if stats.last_src_addr:
        live.add_row("Source addr:", stats.last_src_addr)

    # TTL / hop count
    if stats.last_recv_ttl is not None and stats.last_orig_ttl is not None:
        hops = stats.last_orig_ttl - stats.last_recv_ttl
        if hops == 0:
            ttl_str = (
                f"recv {stats.last_recv_ttl}  [dim](sender set {stats.last_orig_ttl}, same subnet)[/]"
            )
        elif hops > 0:
            ttl_str = (
                f"recv {stats.last_recv_ttl}  "
                f"[dim](sender set {stats.last_orig_ttl},[/] "
                f"[bold]{hops} hop{'s' if hops != 1 else ''} away[/][dim])[/]"
            )
        else:
            ttl_str = (
                f"recv {stats.last_recv_ttl}  "
                f"[yellow](sender set {stats.last_orig_ttl} — TTL increased? suspicious)[/]"
            )
        live.add_row("Received TTL:", ttl_str)
    elif stats.last_recv_ttl is not None:
        live.add_row("Received TTL:", str(stats.last_recv_ttl))

    # DSCP / remarking
    if stats.last_recv_dscp is not None and stats.last_orig_dscp is not None:
        if stats.last_recv_dscp == stats.last_orig_dscp:
            dscp_str = (
                f"{dscp_label(stats.last_recv_dscp)}  "
                f"[dim](preserved)[/]"
            )
        else:
            dscp_str = (
                f"{dscp_label(stats.last_recv_dscp)}  "
                f"[yellow](sender set {dscp_label(stats.last_orig_dscp)} — REMARKED)[/]"
            )
        live.add_row("Received DSCP:", dscp_str)
    elif stats.last_recv_dscp is not None:
        live.add_row("Received DSCP:", dscp_label(stats.last_recv_dscp))

    # ----- quality section -----
    qual = Table.grid(padding=(0, 2))
    qual.add_column(style="dim", no_wrap=True)
    qual.add_column()

    loss_pct = 0.0
    expected_total = stats.packets_recv + stats.packets_lost_total
    if expected_total > 0:
        loss_pct = 100.0 * stats.packets_lost_total / expected_total

    gap_style = "red" if stats.gaps > 0 else ""
    qual.add_row(
        "Gaps detected:",
        f"[{gap_style}]{stats.gaps}[/]" if gap_style else str(stats.gaps),
    )
    loss_style = "red" if stats.packets_lost_total > 0 else ""
    qual.add_row(
        "Packets lost:",
        f"[{loss_style}]{stats.packets_lost_total:,}  ({loss_pct:.2f}%)[/]"
        if loss_style
        else f"{stats.packets_lost_total:,}  ({loss_pct:.2f}%)",
    )
    dup_style = "yellow" if stats.duplicates > 0 else ""
    qual.add_row(
        "Duplicates:",
        f"[{dup_style}]{stats.duplicates}[/]" if dup_style else str(stats.duplicates),
    )
    qual.add_row(
        "Reordered:",
        f"[yellow]{stats.reordered}[/]" if stats.reordered else "0",
    )
    sender_ids = ", ".join(f"0x{sid:08x}" for sid in list(stats.senders.keys())[:3])
    if len(stats.senders) > 3:
        sender_ids += f" (+{len(stats.senders) - 3} more)"
    qual.add_row("Senders seen:", f"{len(stats.senders)}  [dim]({sender_ids or '—'})[/]")
    if stats.sender_restarts > 0:
        qual.add_row(
            "Sender restarts:",
            f"[yellow]{stats.sender_restarts}[/]",
        )
    if stats.foreign_packets > 0:
        qual.add_row(
            "Foreign packets:",
            f"[dim]{stats.foreign_packets}  (not mcast-tools format)[/]",
        )

    # ----- gap event log -----
    log_table = None
    if stats.gap_events:
        log_table = Table.grid(padding=(0, 1))
        log_table.add_column(style="dim")
        log_table.add_column()
        for ev in list(stats.gap_events)[:3]:
            when = time.strftime("%H:%M:%S", time.localtime(time.time() - (time.monotonic() - ev.started_at)))
            if ev.ended_at is None:
                log_table.add_row(when, f"[red]gap ongoing — {ev.duration():.1f}s[/]")
            else:
                log_table.add_row(when, f"recovered after {ev.duration():.1f}s")

    body = Table.grid(padding=(0, 0))
    body.add_column()
    body.add_row(cfg)
    body.add_row(Text("─" * 60, style="dim"))
    body.add_row(live)
    body.add_row(Text("─" * 60, style="dim"))
    body.add_row(Text("Quality", style="bold dim"))
    body.add_row(qual)
    if log_table is not None:
        body.add_row(Text("─" * 60, style="dim"))
        body.add_row(Text("Recent gaps", style="bold dim"))
        body.add_row(log_table)

    return Panel(
        body,
        title="[bold]mcast-receive[/]",
        subtitle="[dim]Ctrl-C to stop[/]",
        border_style="cyan",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    # ---- Validate group ---------------------------------------------------
    try:
        group_addr = validate_multicast_group(args.group)
    except ValueError as e:
        console.print(f"[red]error:[/] {e}")
        return 2
    group_class = classify_multicast_group(group_addr)

    # ---- Resolve source ---------------------------------------------------
    source_arg = args.source_flag if args.source_flag is not None else args.source
    source_ip: Optional[str] = None
    if source_arg:
        try:
            source_addr = validate_source(source_arg)
        except ValueError as e:
            console.print(f"[red]error:[/] {e}")
            return 2
        source_ip = str(source_addr)

    # ---- Resolve IGMP version --------------------------------------------
    igmp_version = (
        args.igmp_version_flag
        if args.igmp_version_flag is not None
        else args.igmp_version
    )
    if igmp_version is None:
        igmp_version = DEFAULT_IGMP_VERSION

    # SSM requires v3
    if source_ip and igmp_version != 3:
        console.print(
            f"[red]error:[/] source-specific (SSM) joins require IGMPv3, "
            f"got v{igmp_version}. Reason: only IGMPv3 Membership Reports carry "
            "the (S,G) state needed for source filtering. Drop --igmp-version "
            "or set it to 3."
        )
        return 2

    # SSM group without source is unusual — warn (but allow; this exercises
    # things like the kernel falling back to (*,G) on a 232/8 group)
    if is_ssm_group(group_addr) and not source_ip:
        console.print(
            f"[yellow]warning:[/] {group_addr} is in the SSM range (232.0.0.0/8) "
            "but no source specified. Most networks ignore (*,G) joins on this range."
        )

    # ---- Resolve interface ------------------------------------------------
    iface_name = args.interface
    iface_ip: Optional[str] = None
    if iface_name:
        from .sender import get_interface_ip
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

    # ---- Force IGMP version ----------------------------------------------
    saved_igmp: Optional[int] = None
    igmp_forced = False
    if iface_name:
        saved_igmp = read_force_igmp_version(iface_name)
        if saved_igmp is None:
            console.print(
                f"[yellow]warning:[/] cannot read force_igmp_version for "
                f"{iface_name} — IGMP version may not match requested v{igmp_version}"
            )
        else:
            if not require_root_or_warn(
                f"forcing IGMPv{igmp_version} on {iface_name}"
            ):
                pass
            ok = write_force_igmp_version(iface_name, igmp_version)
            if ok:
                igmp_forced = True
            elif saved_igmp != igmp_version:
                console.print(
                    f"[yellow]warning:[/] could not write force_igmp_version "
                    f"on {iface_name} (need root). Continuing — kernel will use "
                    f"its current setting (v{saved_igmp or '?'})."
                )

    # ---- Set up socket and join ------------------------------------------
    try:
        sock = setup_receiver_socket(
            group=str(group_addr),
            source=source_ip,
            interface_ip=iface_ip,
        )
    except OSError as e:
        console.print(f"[red]socket/join failed:[/] {e}")
        if igmp_forced and saved_igmp is not None and iface_name:
            write_force_igmp_version(iface_name, saved_igmp)
        return 1

    join_type = (
        f"(S,G) — SSM — source {source_ip}" if source_ip else "(*,G) — ASM"
    )

    stats = ReceiverStats()
    stop_event = threading.Event()

    def handle_signal(signum, frame):
        stop_event.set()

    import signal as _signal
    _signal.signal(_signal.SIGINT, handle_signal)
    _signal.signal(_signal.SIGTERM, handle_signal)

    if args.quiet:
        console.print(
            f"mcast-receive: joining {group_addr}"
            + (f" source {source_ip}" if source_ip else "")
            + f" on {iface_name or 'routing default'} as IGMPv{igmp_version}"
        )

    recv_thread = threading.Thread(
        target=recv_loop,
        kwargs=dict(
            sock=sock,
            stats=stats,
            stop_event=stop_event,
            stall_timeout=args.stall_timeout,
            duration=args.duration,
        ),
        daemon=True,
        name="mcast-receive-rx",
    )
    recv_thread.start()

    try:
        if args.quiet:
            recv_thread.join()
        else:
            with Live(
                render_dashboard(
                    group=str(group_addr),
                    group_class=group_class,
                    source=source_ip,
                    join_type=join_type,
                    interface=iface_name or "",
                    iface_ip=iface_ip,
                    requested_igmp=igmp_version,
                    observed_igmp=(
                        get_interface_igmp_version(iface_name) if iface_name else None
                    ),
                    stats=stats,
                    stall_timeout=args.stall_timeout,
                    running=True,
                ),
                console=console,
                refresh_per_second=4,
                transient=False,
            ) as live:
                while recv_thread.is_alive():
                    live.update(
                        render_dashboard(
                            group=str(group_addr),
                            group_class=group_class,
                            source=source_ip,
                            join_type=join_type,
                            interface=iface_name or "",
                            iface_ip=iface_ip,
                            requested_igmp=igmp_version,
                            observed_igmp=(
                                get_interface_igmp_version(iface_name)
                                if iface_name
                                else None
                            ),
                            stats=stats,
                            stall_timeout=args.stall_timeout,
                            running=True,
                        )
                    )
                    recv_thread.join(timeout=0.25)
    finally:
        sock.close()
        if igmp_forced and saved_igmp is not None and iface_name:
            write_force_igmp_version(iface_name, saved_igmp)

    # ---- Final summary ----------------------------------------------------
    if args.json:
        summary = {
            "tool": "mcast-receive",
            "version": __version__,
            "group": str(group_addr),
            "source": source_ip,
            "interface": iface_name,
            "igmp_version_requested": igmp_version,
            "elapsed_s": stats.elapsed(),
            "packets_recv": stats.packets_recv,
            "bytes_recv": stats.bytes_recv,
            "packets_lost": stats.packets_lost_total,
            "duplicates": stats.duplicates,
            "reordered": stats.reordered,
            "gaps": stats.gaps,
            "sender_restarts": stats.sender_restarts,
            "senders_seen": len(stats.senders),
            "foreign_packets": stats.foreign_packets,
            "last_recv_ttl": stats.last_recv_ttl,
            "last_orig_ttl": stats.last_orig_ttl,
            "last_recv_dscp": stats.last_recv_dscp,
            "last_orig_dscp": stats.last_orig_dscp,
        }
        print(json.dumps(summary))
    elif args.quiet:
        console.print(
            f"recv {stats.packets_recv:,} packets / "
            f"{fmt_bytes(stats.bytes_recv)} in "
            f"{fmt_duration(stats.elapsed())} "
            f"(lost={stats.packets_lost_total}, dup={stats.duplicates}, "
            f"reorder={stats.reordered}, gaps={stats.gaps})"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
