"""Shared utilities for mcast-tools.

Provides:
- Custom packet header definition (struct format, encode/decode)
- Multicast address validation
- Route lookup via `ip -j route get`
- IGMP version sysctl management (read/force/restore)
- Human-readable formatting helpers
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Packet format
# ---------------------------------------------------------------------------
#
# All fields network byte order (big-endian).
#
#   uint32  magic        0x4D434153 ("MCAS")
#   uint32  version      protocol version (currently 1)
#   uint64  seq          sequence number, starts at 0
#   uint64  send_ns      sender monotonic timestamp (nanoseconds)
#   uint32  sender_id    random ID per sender invocation (detect restart)
#   uint16  payload_len  bytes of payload following header
#   uint8   orig_ttl     TTL the sender set on outgoing socket
#   uint8   orig_dscp    DSCP the sender set on outgoing socket
#
# Total: 32 bytes. Followed by `payload_len` bytes of padding.

PACKET_MAGIC = 0x4D434153  # "MCAS"
PROTOCOL_VERSION = 1
HEADER_STRUCT = struct.Struct("!IIQQIHBB")
HEADER_SIZE = HEADER_STRUCT.size  # 32

assert HEADER_SIZE == 32, f"Header size drift: {HEADER_SIZE}"


@dataclass
class PacketHeader:
    """Decoded mcast-tools packet header."""

    magic: int
    version: int
    seq: int
    send_ns: int
    sender_id: int
    payload_len: int
    orig_ttl: int
    orig_dscp: int

    @classmethod
    def decode(cls, buf: bytes) -> Optional["PacketHeader"]:
        """Decode a header from a buffer. Returns None if magic/version mismatch."""
        if len(buf) < HEADER_SIZE:
            return None
        magic, version, seq, send_ns, sender_id, payload_len, orig_ttl, orig_dscp = (
            HEADER_STRUCT.unpack_from(buf, 0)
        )
        if magic != PACKET_MAGIC:
            return None
        if version != PROTOCOL_VERSION:
            return None
        return cls(
            magic=magic,
            version=version,
            seq=seq,
            send_ns=send_ns,
            sender_id=sender_id,
            payload_len=payload_len,
            orig_ttl=orig_ttl,
            orig_dscp=orig_dscp,
        )

    def encode(self) -> bytes:
        return HEADER_STRUCT.pack(
            self.magic,
            self.version,
            self.seq,
            self.send_ns,
            self.sender_id,
            self.payload_len,
            self.orig_ttl,
            self.orig_dscp,
        )


def make_packet(
    seq: int,
    send_ns: int,
    sender_id: int,
    orig_ttl: int,
    orig_dscp: int,
    datagram_size: int,
) -> bytes:
    """Build a full datagram of `datagram_size` bytes (header + padding)."""
    if datagram_size < HEADER_SIZE:
        raise ValueError(
            f"datagram_size {datagram_size} too small (min {HEADER_SIZE})"
        )
    payload_len = datagram_size - HEADER_SIZE
    header = HEADER_STRUCT.pack(
        PACKET_MAGIC,
        PROTOCOL_VERSION,
        seq,
        send_ns,
        sender_id,
        payload_len,
        orig_ttl,
        orig_dscp,
    )
    # Deterministic padding pattern — easier to eyeball in a packet capture.
    padding = b"\xA5" * payload_len
    return header + padding


# ---------------------------------------------------------------------------
# Multicast address validation
# ---------------------------------------------------------------------------

# Either address family. IPv6 addresses may carry a zone id (ff02::1%eth1).
MulticastAddress = "ipaddress.IPv4Address | ipaddress.IPv6Address"


def validate_multicast_group(
    group: str,
) -> "ipaddress.IPv4Address | ipaddress.IPv6Address":
    """Validate `group` is an IPv4 or IPv6 multicast address.

    Returns the address object. IPv6 addresses may include a zone id
    (``ff02::42%eth1``) — preserved on the returned object's ``scope_id``.

    Raises ValueError with a friendly message on failure.
    """
    try:
        addr = ipaddress.ip_address(group)
    except ValueError:
        raise ValueError(f"'{group}' is not a valid IP address")
    if not addr.is_multicast:
        if isinstance(addr, ipaddress.IPv4Address):
            raise ValueError(
                f"'{group}' is not a multicast address "
                f"(IPv4 multicast range is 224.0.0.0/4)"
            )
        raise ValueError(
            f"'{group}' is not a multicast address "
            f"(IPv6 multicast range is ff00::/8)"
        )
    return addr


def split_scope(
    addr: ipaddress.IPv6Address,
) -> "tuple[ipaddress.IPv6Address, Optional[str]]":
    """Split an IPv6 address into (unscoped address, zone-or-None).

    ``ff02::1%eth1`` → (``ff02::1``, ``"eth1"``). The unscoped form is what
    classification, range checks, and ``inet_pton`` want; the zone names the
    interface for socket-level scope resolution.
    """
    zone = getattr(addr, "scope_id", None)
    if zone:
        # Rebuilding from packed bytes drops the zone cleanly.
        return ipaddress.IPv6Address(addr.packed), zone
    return addr, None


# RFC 4291 §2.7 — IPv6 multicast scope field (low nibble of byte 1).
_V6_SCOPE_NAMES = {
    0x1: "interface-local",
    0x2: "link-local",
    0x3: "realm-local",
    0x4: "admin-local",
    0x5: "site-local",
    0x8: "organization-local",
    0xE: "global",
}

# Solicited-node multicast (RFC 4291 §2.7.1): ff02::1:ff00:0/104.
_V6_SOLICITED_NODE = ipaddress.IPv6Network("ff02::1:ff00:0/104")

# RFC 4607 — the IPv6 SSM range is ff3x::/32 for every scope x,
# i.e. flags nibble == 3 (P=1, T=1), which is exactly ff30::/12.
_V6_SSM_RANGE = ipaddress.IPv6Network("ff30::/12")


def _classify_v6(addr: ipaddress.IPv6Address) -> str:
    """Classify an IPv6 multicast group by flags nibble + scope (RFC 4291)."""
    unscoped, _zone = split_scope(addr)
    b = unscoped.packed
    flags = (b[1] >> 4) & 0xF
    scope = b[1] & 0xF
    scope_str = _V6_SCOPE_NAMES.get(scope, f"scope-{scope:x}")
    # Interface-local and link-local scopes never cross a router.
    if scope in (0x1, 0x2):
        scope_str += " scope (not routed)"
    else:
        scope_str += " scope"

    if unscoped in _V6_SOLICITED_NODE:
        kind = "solicited-node"
    elif flags == 0x3:
        kind = "SSM (source-specific)"
    elif flags & 0x4:
        kind = "embedded-RP"
    elif flags & 0x2:
        kind = "unicast-prefix-based"
    elif flags & 0x1:
        kind = "transient"
    else:
        kind = "well-known"
    return f"{kind}, {scope_str}"


def v6_scope_nibble(addr: ipaddress.IPv6Address) -> int:
    """Return the RFC 4291 scope nibble (low nibble of byte 1) of a v6 group."""
    unscoped, _zone = split_scope(addr)
    return unscoped.packed[1] & 0xF


def needs_explicit_interface(addr: ipaddress.IPv6Address) -> bool:
    """True for interface-local (1) and link-local (2) scoped groups.

    These never appear in the routing table in a useful way — the kernel
    needs to be told which interface, via a %zone, --interface, or an
    IPV6_MULTICAST_IF/scope_id we resolve ourselves.
    """
    return v6_scope_nibble(addr) in (0x1, 0x2)


def classify_multicast_group(
    addr: "ipaddress.IPv4Address | ipaddress.IPv6Address",
) -> str:
    """Return a short human-readable scope/classification for an mcast group."""
    if isinstance(addr, ipaddress.IPv6Address):
        return _classify_v6(addr)
    if addr in ipaddress.IPv4Network("224.0.0.0/24"):
        return "link-local (not routed)"
    if addr in ipaddress.IPv4Network("232.0.0.0/8"):
        return "SSM (source-specific)"
    if addr in ipaddress.IPv4Network("233.0.0.0/8"):
        return "GLOP"
    if addr in ipaddress.IPv4Network("239.0.0.0/8"):
        return "admin-scoped"
    return "any-source multicast"


def is_ssm_group(
    addr: "ipaddress.IPv4Address | ipaddress.IPv6Address",
) -> bool:
    if isinstance(addr, ipaddress.IPv6Address):
        unscoped, _zone = split_scope(addr)
        return unscoped in _V6_SSM_RANGE
    return addr in ipaddress.IPv4Network("232.0.0.0/8")


def validate_source(
    source: str,
    group: "ipaddress.IPv4Address | ipaddress.IPv6Address",
) -> "ipaddress.IPv4Address | ipaddress.IPv6Address":
    """Validate an SSM source address against the group's address family.

    The source must be unicast, zone-free, and in the same family as the
    group — an (S,G) pair can't straddle IPv4 and IPv6.
    """
    try:
        addr = ipaddress.ip_address(source)
    except ValueError:
        raise ValueError(f"'{source}' is not a valid IP address")
    if isinstance(addr, ipaddress.IPv6Address) and getattr(addr, "scope_id", None):
        raise ValueError(
            f"Source '{source}' carries a %zone — sources should be plain "
            "addresses. Pick the interface via the group's zone or --interface."
        )
    if addr.version != group.version:
        raise ValueError(
            f"Source '{source}' is IPv{addr.version} but the group is "
            f"IPv{group.version} — an (S,G) pair must share one address family"
        )
    if addr.is_multicast:
        raise ValueError(
            f"Source '{source}' is a multicast address — sources must be unicast"
        )
    return addr


# ---------------------------------------------------------------------------
# IPv6 multicast join structures
# ---------------------------------------------------------------------------
#
# Python's socket module exposes IPV6_JOIN_GROUP but (on many builds) not the
# protocol-independent MCAST_* options, and there is no IPv6 equivalent of
# IP_ADD_SOURCE_MEMBERSHIP — IPv6 SSM joins go through MCAST_JOIN_SOURCE_GROUP
# with a struct group_source_req. We pack both structures by hand against the
# Linux UAPI layout (include/uapi/linux/in.h, in6.h); see
# tests/test_join_structs.py for the byte-precise layout contract.

# Linux include/uapi/linux/in.h
MCAST_JOIN_SOURCE_GROUP = getattr(socket, "MCAST_JOIN_SOURCE_GROUP", 46)

_SOCKADDR_STORAGE_SIZE = 128
GROUP_SOURCE_REQ_SIZE = 8 + 2 * _SOCKADDR_STORAGE_SIZE  # 264 on x86_64


def pack_ipv6_mreq(group: ipaddress.IPv6Address, ifindex: int) -> bytes:
    """Pack struct ipv6_mreq for IPV6_JOIN_GROUP (ASM join).

    ifindex 0 lets the kernel pick the interface.
    """
    unscoped, _zone = split_scope(group)
    return struct.pack("=16si", unscoped.packed, ifindex)


def _pack_sockaddr_in6_storage(
    addr: ipaddress.IPv6Address, scope_id: int = 0
) -> bytes:
    """Pack a sockaddr_in6 inside a zeroed 128-byte sockaddr_storage."""
    unscoped, _zone = split_scope(addr)
    sa = struct.pack(
        "=H",  # sa_family_t — native byte order
        socket.AF_INET6,
    )
    sa += struct.pack("!HI", 0, 0)  # sin6_port, sin6_flowinfo — zero for joins
    sa += unscoped.packed  # sin6_addr
    sa += struct.pack("=I", scope_id)  # sin6_scope_id — native byte order
    return sa.ljust(_SOCKADDR_STORAGE_SIZE, b"\x00")


def pack_group_source_req(
    ifindex: int,
    group: ipaddress.IPv6Address,
    source: ipaddress.IPv6Address,
    group_scope_id: int = 0,
) -> bytes:
    """Pack struct group_source_req for MCAST_JOIN_SOURCE_GROUP (SSM join).

    Layout (x86_64): u32 gsr_interface, 4 pad bytes (storage is 8-aligned),
    then two 128-byte sockaddr_storage blocks (group, source) = 264 bytes.
    """
    buf = struct.pack("=I4x", ifindex)
    buf += _pack_sockaddr_in6_storage(group, scope_id=group_scope_id)
    buf += _pack_sockaddr_in6_storage(source)
    assert len(buf) == GROUP_SOURCE_REQ_SIZE, (
        f"group_source_req size drift: {len(buf)}"
    )
    return buf


# ---------------------------------------------------------------------------
# Route lookup — figure out which interface a multicast group will egress on
# ---------------------------------------------------------------------------

@dataclass
class RouteInfo:
    interface: str
    src_addr: Optional[str]  # preferred source IP

    @classmethod
    def for_destination(cls, dest: str) -> Optional["RouteInfo"]:
        """Run `ip -j route get <dest>` and parse the result. Returns None on failure."""
        try:
            result = subprocess.run(
                ["ip", "-j", "route", "get", dest],
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
        entry = data[0]
        iface = entry.get("dev")
        if not iface:
            return None
        return cls(interface=iface, src_addr=entry.get("prefsrc"))


# ---------------------------------------------------------------------------
# IGMP version control
# ---------------------------------------------------------------------------

def igmp_force_path(interface: str) -> Path:
    return Path(f"/proc/sys/net/ipv4/conf/{interface}/force_igmp_version")


def read_force_igmp_version(interface: str) -> Optional[int]:
    """Read current force_igmp_version sysctl. Returns None if path missing."""
    p = igmp_force_path(interface)
    try:
        return int(p.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError):
        return None


def write_force_igmp_version(interface: str, version: int) -> bool:
    """Force IGMP version on an interface. Requires root. Returns True on success.

    version=0 means "auto" (kernel default — usually v3).
    """
    if version not in (0, 1, 2, 3):
        raise ValueError(f"Invalid IGMP version: {version}")
    p = igmp_force_path(interface)
    try:
        p.write_text(f"{version}\n")
        return True
    except (FileNotFoundError, PermissionError):
        return False


def parse_proc_net_igmp() -> dict[str, dict]:
    """Parse /proc/net/igmp into a structured dict keyed by interface name.

    The file looks like::

        Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter
        1\tlo        :     1      V3
        \t\t\t\t010000E0     1 0:00000000\t\t0
        2\teth0      :     1      V3
        \t\t\t\t010000E0     1 0:00000000\t\t0

    Despite the header column naming, per-interface rows really carry only
    "count" and the operational IGMP version. Group rows are indented and
    contain hex address (host byte order), users, timer, and reporter.

    Returns:
        {
            "eth0": {
                "version": "V3",
                "groups": [
                    {"address": "224.0.0.1", "users": 1, "timer": "0:00000000",
                     "reporter": "0"},
                    ...
                ]
            },
            ...
        }
    """
    try:
        raw = Path("/proc/net/igmp").read_text()
    except (FileNotFoundError, PermissionError):
        return {}

    interfaces: dict[str, dict] = {}
    current_iface: Optional[str] = None

    for line in raw.splitlines():
        if not line.strip():
            continue
        # Header line begins with literal "Idx"
        if line.startswith("Idx"):
            continue
        # Per-interface lines start with the index digit (no leading whitespace)
        # and contain a colon separating "idx device" from "count version".
        if not (line.startswith("\t") or line.startswith(" ")):
            if ":" not in line:
                continue
            left, right = line.split(":", 1)
            left_parts = re.split(r"\s+", left.strip())
            right_parts = re.split(r"\s+", right.strip())
            # left: [idx, device]  right: [count, version]
            if len(left_parts) >= 2 and len(right_parts) >= 2:
                iface = left_parts[1]
                version = right_parts[-1]
                current_iface = iface
                interfaces[iface] = {
                    "version": version,
                    "groups": [],
                }
            continue
        # Group lines are indented. Format: hex_addr users timer reporter
        if current_iface is None:
            continue
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 4:
            continue
        hex_addr = parts[0]
        try:
            users = int(parts[1])
        except ValueError:
            continue
        timer = parts[2]
        reporter = parts[3]
        # Hex address is in host byte order (little-endian on x86_64); reverse
        # the bytes to produce the conventional dotted-quad representation.
        try:
            raw_bytes = bytes.fromhex(hex_addr)
            if len(raw_bytes) == 4:
                dotted = ".".join(str(b) for b in reversed(raw_bytes))
            else:
                dotted = hex_addr
        except ValueError:
            dotted = hex_addr
        interfaces[current_iface]["groups"].append(
            {
                "address": dotted,
                "users": users,
                "timer": timer,
                "reporter": reporter,
            }
        )
    return interfaces


def get_interface_igmp_version(interface: str) -> Optional[str]:
    """Read the operational IGMP version for an interface from /proc/net/igmp."""
    info = parse_proc_net_igmp()
    iface_info = info.get(interface)
    if iface_info:
        return iface_info.get("version")
    return None


# ---------------------------------------------------------------------------
# MLD version control (IPv6's IGMP analog)
# ---------------------------------------------------------------------------
#
# MLDv1 ≈ IGMPv2 (ASM only); MLDv2 ≈ IGMPv3 (adds SSM source filtering).
# There is no MLD analog of IGMPv1. force_mld_version: 0 = auto (kernel
# default is MLDv2, subject to v1-querier compatibility fallback on the
# link), 1 = MLDv1, 2 = MLDv2.

def mld_force_path(interface: str) -> Path:
    return Path(f"/proc/sys/net/ipv6/conf/{interface}/force_mld_version")


def read_force_mld_version(interface: str) -> Optional[int]:
    """Read current force_mld_version sysctl. Returns None if path missing
    (including hosts where IPv6 is disabled at the kernel level)."""
    p = mld_force_path(interface)
    try:
        return int(p.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError):
        return None


def write_force_mld_version(interface: str, version: int) -> bool:
    """Force MLD version on an interface. Requires root. Returns True on success.

    version=0 means "auto" (kernel default — MLDv2).
    """
    if version not in (0, 1, 2):
        raise ValueError(f"Invalid MLD version: {version}")
    p = mld_force_path(interface)
    try:
        p.write_text(f"{version}\n")
        return True
    except (FileNotFoundError, PermissionError):
        return False


# ---------------------------------------------------------------------------
# /proc/net/igmp6 parsing (IPv6 multicast memberships)
# ---------------------------------------------------------------------------

_IGMP6_PROC_PATH = Path("/proc/net/igmp6")


def _parse_igmp6_text(raw: str) -> dict[str, dict]:
    """Parse /proc/net/igmp6 content into a dict keyed by interface name.

    Unlike /proc/net/igmp, the IPv6 file is flat — no header line, no
    per-interface section rows, and (mercifully) addresses are plain
    network-order hex with no byte-swapping. Kernel format per line
    (net/ipv6/mcast.c)::

        ifindex ifname <32-hex-group> users flags timer

    e.g. ``33   eth1   ff020000000000000000000000000001   1 0000000C 0``

    There is also no MLD version column — the operational MLD version is
    not exposed here, only the force_mld_version sysctl reflects forcing.

    Returns::

        {
            "eth1": {
                "ifindex": 33,
                "groups": [
                    {"address": "ff02::1", "users": 1, "flags": "0000000C"},
                    ...
                ]
            },
            ...
        }
    """
    interfaces: dict[str, dict] = {}
    for line in raw.splitlines():
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 5:
            continue
        ifindex_s, ifname, hex_addr, users_s, flags = parts[:5]
        if len(hex_addr) != 32:
            continue
        try:
            ifindex = int(ifindex_s)
            users = int(users_s)
            addr = ipaddress.IPv6Address(bytes.fromhex(hex_addr))
        except ValueError:
            continue
        entry = interfaces.setdefault(
            ifname, {"ifindex": ifindex, "groups": []}
        )
        entry["groups"].append(
            {
                "address": str(addr),
                "users": users,
                "flags": flags,
            }
        )
    return interfaces


def parse_proc_net_igmp6() -> dict[str, dict]:
    """Read and parse /proc/net/igmp6. Returns {} if unavailable (e.g. on
    hosts with IPv6 disabled at the kernel level)."""
    try:
        raw = _IGMP6_PROC_PATH.read_text()
    except (FileNotFoundError, PermissionError):
        return {}
    return _parse_igmp6_text(raw)


# ---------------------------------------------------------------------------
# Rate parsing
# ---------------------------------------------------------------------------

_RATE_RE = re.compile(
    r"^\s*(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>pps|bps|kbps|mbps|gbps|kpps|mpps)?\s*$",
    re.IGNORECASE,
)


def parse_rate(rate_str: str, datagram_size: int) -> float:
    """Parse a rate string like '25pps' or '1Mbps' to packets-per-second (float).

    `datagram_size` is used to convert bps -> pps. We use the UDP payload size,
    NOT including IP+UDP header overhead (28 bytes), since that's the user's
    mental model — they're configuring application-layer bytes.
    """
    m = _RATE_RE.match(rate_str)
    if not m:
        raise ValueError(
            f"Could not parse rate '{rate_str}'. "
            f"Examples: '25pps', '500pps', '1Mbps', '100kbps'"
        )
    num = float(m.group("num"))
    unit = (m.group("unit") or "pps").lower()

    if unit == "pps":
        return num
    if unit == "kpps":
        return num * 1000
    if unit == "mpps":
        return num * 1_000_000
    if unit == "bps":
        bps = num
    elif unit == "kbps":
        bps = num * 1000
    elif unit == "mbps":
        bps = num * 1_000_000
    elif unit == "gbps":
        bps = num * 1_000_000_000
    else:
        raise ValueError(f"Unknown rate unit: {unit}")
    bytes_per_packet = datagram_size
    pps = bps / (bytes_per_packet * 8)
    if pps < 1:
        raise ValueError(
            f"Rate '{rate_str}' yields {pps:.3f} pps at {datagram_size}-byte "
            f"datagrams — too slow to be meaningful (min 1 pps)"
        )
    return pps


# ---------------------------------------------------------------------------
# DSCP / TOS helpers
# ---------------------------------------------------------------------------

DSCP_NAMES = {
    "be": 0, "cs0": 0,
    "cs1": 8, "af11": 10, "af12": 12, "af13": 14,
    "cs2": 16, "af21": 18, "af22": 20, "af23": 22,
    "cs3": 24, "af31": 26, "af32": 28, "af33": 30,
    "cs4": 32, "af41": 34, "af42": 36, "af43": 38,
    "cs5": 40, "ef": 46,
    "cs6": 48, "cs7": 56,
}

DSCP_NAME_LOOKUP = {v: k.upper() for k, v in DSCP_NAMES.items()}


def parse_dscp(s: str) -> int:
    """Parse a DSCP value — accepts numeric (0-63) or symbolic name (ef, af41, ...)."""
    s_low = s.strip().lower()
    if s_low in DSCP_NAMES:
        return DSCP_NAMES[s_low]
    try:
        v = int(s_low, 0)
    except ValueError:
        raise ValueError(
            f"Unknown DSCP value '{s}'. Use a number 0-63 or a name "
            f"(be, cs1-cs7, af11-af43, ef)."
        )
    if not 0 <= v <= 63:
        raise ValueError(f"DSCP {v} out of range (0-63)")
    return v


def dscp_label(dscp: int) -> str:
    """Render a DSCP value as e.g. 'EF (46)' or '0 (BE)'."""
    name = DSCP_NAME_LOOKUP.get(dscp)
    if name:
        return f"{name} ({dscp})"
    return f"{dscp}"


def dscp_from_tos_byte(tos: int) -> int:
    """Extract DSCP from a TOS byte (upper 6 bits)."""
    return (tos & 0xFC) >> 2


def tos_byte_from_dscp(dscp: int) -> int:
    return (dscp & 0x3F) << 2


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def fmt_bytes(n: int) -> str:
    """Format a byte count as a human-readable string with SI prefixes (KB/MB/GB)."""
    if n < 1000:
        return f"{n} B"
    if n < 1_000_000:
        return f"{n/1000:.2f} KB"
    if n < 1_000_000_000:
        return f"{n/1_000_000:.2f} MB"
    return f"{n/1_000_000_000:.2f} GB"


def fmt_bps(bps: float) -> str:
    if bps < 1000:
        return f"{bps:.0f} bps"
    if bps < 1_000_000:
        return f"{bps/1000:.2f} kbps"
    if bps < 1_000_000_000:
        return f"{bps/1_000_000:.2f} Mbps"
    return f"{bps/1_000_000_000:.2f} Gbps"


def fmt_duration(seconds: float) -> str:
    """Format seconds as HH:MM:SS."""
    if seconds < 0:
        seconds = 0
    total = int(seconds)
    h = total // 3600
    m = (total % 3600) // 60
    s = total % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_pps(pps: float) -> str:
    if pps < 1000:
        return f"{pps:.2f} pps"
    if pps < 1_000_000:
        return f"{pps/1000:.2f} kpps"
    return f"{pps/1_000_000:.2f} Mpps"


# ---------------------------------------------------------------------------
# Privilege checks
# ---------------------------------------------------------------------------

def require_root_or_warn(action: str) -> bool:
    """Return True if running as root, False with a stderr warning otherwise."""
    if os.geteuid() == 0:
        return True
    print(
        f"WARNING: not running as root — {action} may fail or be ignored.",
        file=sys.stderr,
    )
    return False
