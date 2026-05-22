"""mcast-status — snapshot of current multicast group memberships on this host.

Pretty-prints /proc/net/igmp showing which interfaces are subscribed to which
groups, the operating IGMP version, and the current force_igmp_version setting.
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
    read_force_igmp_version,
)


# Groups the kernel always joins — noise we hide by default
_NOISE_GROUPS = {
    "224.0.0.1",  # all-hosts
    "224.0.0.251",  # mDNS (often kernel-side)
    "239.255.255.250",  # SSDP
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcast-status",
        description=(
            "Show current IPv4 multicast group memberships on this host "
            "(from /proc/net/igmp). Helpful for verifying a mcast-receive "
            "join actually landed."
        ),
    )
    p.add_argument(
        "--all", "-a",
        action="store_true",
        help="Include kernel-default groups (224.0.0.1, 224.0.0.251, etc.)",
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
    if not info:
        console.print(
            "[yellow]No IGMP info available[/]  "
            "[dim](could not read /proc/net/igmp)[/]"
        )
        return 1

    if args.interface:
        info = {k: v for k, v in info.items() if k == args.interface}
        if not info:
            console.print(
                f"[yellow]Interface {args.interface!r} not found in /proc/net/igmp[/]"
            )
            return 1

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
            "[dim]No non-default multicast memberships on this host.[/]  "
            "[dim](pass --all to include kernel defaults)[/]"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
