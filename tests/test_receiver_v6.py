"""Tests for mcast-receive's IPv6 support.

Two kinds of fixtures here, labeled per the don't-fabricate-test-input
discipline:

- The IPv4 ancillary-data tuples are a REAL capture: a live loopback
  recvmsg on this very host (sender stamped TTL=77, TOS=0xB8/EF), taken
  2026-06-11. They lock the v0.1.0 parse behavior as a regression guard.
- The IPv6 ancillary tuples are SYNTHETIC, constructed byte-for-byte from
  the kernel ABI (IPV6_HOPLIMIT=52 and IPV6_TCLASS=67 cmsgs each carry a
  native 4-byte int — RFC 3542 §6 / linux/ipv6.h). The sandbox kernel has
  IPv6 disabled, so a live v6 capture is impossible here; wire-level
  confirmation is part of the pre-tag lab verification.

CLI family-rule tests run through main() and must exit (rc=2) during
validation — *before* any socket is created — which is what makes them
testable on a host without IPv6.
"""
import socket
import struct

import pytest

from mcast_tools import receiver
from mcast_tools.receiver import (
    DEFAULT_IGMP_VERSION,
    DEFAULT_MLD_VERSION,
    build_parser,
    parse_ancillary,
)

IPPROTO_IPV6 = socket.IPPROTO_IPV6  # 41
CMSG_IPV6_HOPLIMIT = 52
CMSG_IPV6_TCLASS = 67


# ---------------------------------------------------------------------------
# parse_ancillary — IPv4, REAL captured bytes (regression guard)
# ---------------------------------------------------------------------------

# Captured live on this host, 2026-06-11: sender set TTL=77, TOS=0xB8 (EF).
REAL_V4_ANCDATA = [
    (socket.IPPROTO_IP, 2, b"M\x00\x00\x00"),  # IP_TTL cmsg, int 77
    (socket.IPPROTO_IP, 1, b"\xb8"),            # IP_TOS cmsg, byte 184
]


def test_v4_real_ancdata():
    ttl, tos = parse_ancillary(REAL_V4_ANCDATA)
    assert ttl == 77
    assert tos == 0xB8


def test_v4_ttl_only():
    ttl, tos = parse_ancillary([REAL_V4_ANCDATA[0]])
    assert ttl == 77
    assert tos is None


# ---------------------------------------------------------------------------
# parse_ancillary — IPv6, ABI-constructed (lab verification pending)
# ---------------------------------------------------------------------------

def _v6_anc(hoplimit=None, tclass=None):
    anc = []
    if hoplimit is not None:
        anc.append(
            (IPPROTO_IPV6, CMSG_IPV6_HOPLIMIT, struct.pack("=i", hoplimit))
        )
    if tclass is not None:
        anc.append(
            (IPPROTO_IPV6, CMSG_IPV6_TCLASS, struct.pack("=i", tclass))
        )
    return anc


def test_v6_hoplimit_and_tclass():
    ttl, tos = parse_ancillary(_v6_anc(hoplimit=64, tclass=0xB8))
    assert ttl == 64
    assert tos == 0xB8


def test_v6_hoplimit_only():
    ttl, tos = parse_ancillary(_v6_anc(hoplimit=1))
    assert ttl == 1
    assert tos is None


def test_mixed_levels_do_not_collide():
    # A socket only ever delivers its own family's cmsgs, but the parser
    # must not blow up if both appear.
    anc = REAL_V4_ANCDATA + _v6_anc(hoplimit=9)
    ttl, tos = parse_ancillary(anc)
    assert ttl == 9  # last writer wins; order is kernel-defined per family
    assert tos == 0xB8


def test_unknown_levels_and_types_ignored():
    anc = [
        (socket.SOL_SOCKET, 29, b"\x01\x00\x00\x00"),
        (socket.IPPROTO_IP, 99, b"\x00"),
        (IPPROTO_IPV6, 99, b"\x00\x00\x00\x00"),
    ]
    assert parse_ancillary(anc) == (None, None)


def test_truncated_data_safe():
    anc = [
        (socket.IPPROTO_IP, 2, b"\x01"),          # too short for an int
        (IPPROTO_IPV6, CMSG_IPV6_HOPLIMIT, b""),  # empty
        (socket.IPPROTO_IP, 1, b""),              # empty TOS
    ]
    assert parse_ancillary(anc) == (None, None)


# ---------------------------------------------------------------------------
# Parser surface
# ---------------------------------------------------------------------------

def test_mld_version_flag_parses():
    args = build_parser().parse_args(["ff05::1", "--mld-version", "1"])
    assert args.mld_version_flag == 1


def test_mld_version_rejects_3():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["ff05::1", "--mld-version", "3"])


def test_defaults_exposed():
    assert DEFAULT_IGMP_VERSION == 3
    assert DEFAULT_MLD_VERSION == 2


# ---------------------------------------------------------------------------
# main() family rules — all must exit rc=2 during validation, pre-socket
# ---------------------------------------------------------------------------

def test_v6_group_rejects_igmp_version_flag(capsys):
    rc = receiver.main(["ff05::1", "--igmp-version", "3"])
    assert rc == 2
    assert "MLD" in capsys.readouterr().out


def test_v4_group_rejects_mld_version_flag(capsys):
    rc = receiver.main(["239.0.10.101", "--mld-version", "2"])
    assert rc == 2
    assert "IGMP" in capsys.readouterr().out


def test_v6_positional_version_3_is_educational_error(capsys):
    # Full positional grammar: group, source, version. A valid v6 source
    # gets us past source validation so the version-3 check fires.
    rc = receiver.main(["ff3e::8000:1", "2001:db8::5", "3"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "MLD" in out and "2" in out


def test_v6_ssm_requires_mldv2(capsys):
    rc = receiver.main(
        ["ff3e::8000:1", "--source", "2001:db8::5", "--mld-version", "1"]
    )
    assert rc == 2
    out = capsys.readouterr().out
    assert "MLDv2" in out


def test_v6_link_local_requires_interface(capsys):
    rc = receiver.main(["ff02::42"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "interface" in out.lower()


def test_v6_zone_interface_conflict(capsys):
    rc = receiver.main(["ff02::42%eth1", "--interface", "eth2"])
    assert rc == 2
    assert "conflict" in capsys.readouterr().out.lower()


def test_v4_ssm_still_requires_igmpv3(capsys):
    # v0.1.0 regression guard
    rc = receiver.main(
        ["232.5.5.5", "--source", "10.1.1.1", "--igmp-version", "2"]
    )
    assert rc == 2
    assert "IGMPv3" in capsys.readouterr().out
