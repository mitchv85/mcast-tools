"""mcast-status — snapshot of current multicast group memberships on this host.

Pretty-prints /proc/net/igmp (IPv4) and /proc/net/igmp6 (IPv6) showing
which interfaces are subscribed to which groups. The IPv4 table includes
the operating IGMP version; the IPv6 table shows only the *forced* MLD
state — the kernel does not expose the operational MLD version in
/proc/net/igmp6, and we don't pretend otherwise.
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from typing import Optional

from rich.console import Console
from rich.table import Table

from . import __version__
from .common import (
    classify_multicast_group,
    parse_proc_net_igmp,
    parse_proc_net_igmp6,
    read_force_igmp_version,
    read_force_mld_version,
)


# Groups the kernel always joins — noise we hide by default
_NOISE_GROUPS = {
    "224.0.0.1",  # all-hosts
    "224.0.0.251",  # mDNS (often kernel-side)
    "239.255.255.250",  # SSDP
}

# IPv6 kernel-default noise: all-nodes plus the entire solicited-node range
_V6_NOISE_EXACT = {"ff02::1", "ff01::1"}
_V6_SOLICITED_NODE = ipaddress.IPv6Network("ff02::1:ff00:0/104")


def _is_v6_noise(addr_str: str) -> bool:
    """True for groups every IPv6-enabled interface joins automatically:
    all-nodes (ff02::1 / ff01::1) and solicited-node (ff02::1:ffxx:xxxx,
    one per configured address — NDP plumbing, not userspace joins)."""
    if addr_str in _V6_NOISE_EXACT:
        return True
    try:
        return ipaddress.IPv6Address(addr_str) in _V6_SOLICITED_NODE
    except ValueError:
        return False


def v6_rows(
    info6: dict,
    show_all: bool,
    iface_filter: Optional[str],
) -> list:
    """Build (iface, address, users, classification) rows from parsed
    /proc/net/igmp6 data. Pure — forced-MLD lookup happens at render."""
    rows = []
    for iface, data in info6.items():
        if iface == "lo":
            continue
        if iface_filter and iface != iface_filter:
            continue
        for g in data.get("groups", []):
            if not show_all and _is_v6_noise(g["address"]):
                continue
            try:
                clazz = classify_multicast_group(
                    ipaddress.IPv6Address(g["address"])
                )
            except ValueError:
                clazz = "?"
            rows.append((iface, g["address"], g["users"], clazz))
    return rows


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcast-status",
        description=(
            "Show current IPv4 and IPv6 multicast group memberships on this "
            "host (from /proc/net/igmp and /proc/net/igmp6). Helpful for "
            "verifying a mcast-receive join actually landed."
        ),
    )
    p.add_argument(
        "--all", "-a",
        action="store_true",
        help=(
            "Include kernel-default groups (224.0.0.1, ff02::1, "
            "solicited-node, etc.)"
        ),
    )
    p.add_argument(
        "--interface", "-i",
        help="Only show this interface",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"mcast-status {__version__}",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    info = parse_proc_net_igmp()
    info6 = parse_proc_net_igmp6()
    igmp6_available = bool(info6)

    if not info and not info6:
        console.print(
            "[yellow]No multicast membership info available[/]  "
            "[dim](could not read /proc/net/igmp or /proc/net/igmp6)[/]"
        )
        return 1

    if args.interface:
        info = {k: v for k, v in info.items() if k == args.interface}
        info6 = {k: v for k, v in info6.items() if k == args.interface}
        if not info and not info6:
            console.print(
                f"[yellow]Interface {args.interface!r} not found in "
                "/proc/net/igmp or /proc/net/igmp6[/]"
            )
            return 1

    # ---- IPv4 table --------------------------------------------------------
    table = Table(
        title="IPv4 Multicast Memberships",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Interface", style="bold")
    table.add_column("IGMP", justify="center")
    table.add_column("Forced?", justify="center")
    table.add_column("Group")
    table.add_column("Users", justify="right")
    table.add_column("Classification", style="dim")

    any_rows = False
    for iface, data in info.items():
        if iface == "lo":
            continue
        forced = read_force_igmp_version(iface)
        forced_str = (
            "—" if forced in (None, 0) else f"v{forced}"
        )
        groups = data.get("groups", [])
        if not args.all:
            groups = [g for g in groups if g["address"] not in _NOISE_GROUPS]
        if not groups:
            continue
        for g in groups:
            try:
                ga = ipaddress.IPv4Address(g["address"])
                clazz = classify_multicast_group(ga)
            except ValueError:
                clazz = "?"
            table.add_row(
                iface,
                data.get("version", "?"),
                forced_str,
                g["address"],
                str(g["users"]),
                clazz,
            )
            any_rows = True

    if any_rows:
        console.print(table)
    else:
        console.print(
            "[dim]No non-default IPv4 multicast memberships on this host.[/]  "
            "[dim](pass --all to include kernel defaults)[/]"
        )

    # ---- IPv6 table --------------------------------------------------------
    if not info6:
        if igmp6_available:
            console.print(
                "[dim]No IPv6 multicast memberships on this interface.[/]"
            )
        else:
            console.print(
                "[dim]IPv6: /proc/net/igmp6 not available on this host.[/]"
            )
        return 0

    rows6 = v6_rows(info6, show_all=args.all, iface_filter=None)
    if not rows6:
        console.print(
            "[dim]No non-default IPv6 multicast memberships on this host.[/]  "
            "[dim](pass --all to include all-nodes and solicited-node groups)[/]"
        )
        return 0

    table6 = Table(
        title="IPv6 Multicast Memberships",
        show_lines=True,
        header_style="bold cyan",
    )
    table6.add_column("Interface", style="bold")
    table6.add_column("Forced MLD?", justify="center")
    table6.add_column("Group")
    table6.add_column("Users", justify="right")
    table6.add_column("Classification", style="dim")

    forced_cache: dict[str, Optional[int]] = {}
    for iface, addr, users, clazz in rows6:
        if iface not in forced_cache:
            forced_cache[iface] = read_force_mld_version(iface)
        forced6 = forced_cache[iface]
        forced6_str = "—" if forced6 in (None, 0) else f"v{forced6}"
        table6.add_row(iface, forced6_str, addr, str(users), clazz)

    console.print(table6)
    return 0


if __name__ == "__main__":
    sys.exit(main())
