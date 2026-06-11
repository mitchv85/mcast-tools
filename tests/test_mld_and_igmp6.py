"""Tests for /proc/net/igmp6 parsing and MLD version sysctl helpers.

Fixture provenance (per the don't-fabricate-test-input discipline): the
igmp6 fixture is a REAL capture, taken 2026-06-11 from a host-ubuntu
rev1.4 container (Ubuntu 24.04.4 LTS, kernel-side ContainerLab lab host),
not synthesized. Notable real-world details it carries:

- eth1 (ifindex 33) holds TWO global addresses whose low 24 bits collide
  on ...00:b3 — so the solicited-node group ff02::1:ff00:b3 shows
  refcount 2 while ff02::1:ff00:101 shows refcount 1. A synthetic fixture
  would never have thought of that.
- Addresses are straight network-order hex (NO byte-swap, unlike the
  little-endian dance /proc/net/igmp requires for IPv4).
- There is no header line and no per-interface version column — MLD
  operational version is simply not exposed here, which is why
  mcast-status's IPv6 table reports only the *forced* state.
"""
from pathlib import Path

import pytest

from mcast_tools.common import (
    _parse_igmp6_text,
    mld_force_path,
    parse_proc_net_igmp6,
    read_force_mld_version,
    write_force_mld_version,
)

FIXTURE = Path(__file__).parent / "fixtures" / "igmp6_host_ubuntu_2404.txt"


@pytest.fixture
def real_capture() -> str:
    return FIXTURE.read_text()


# ---------------------------------------------------------------------------
# _parse_igmp6_text against the real capture
# ---------------------------------------------------------------------------

def test_interfaces_present(real_capture):
    info = _parse_igmp6_text(real_capture)
    assert set(info.keys()) == {"lo", "eth0", "eth1"}


def test_ifindex_captured(real_capture):
    info = _parse_igmp6_text(real_capture)
    assert info["lo"]["ifindex"] == 1
    assert info["eth0"]["ifindex"] == 2
    assert info["eth1"]["ifindex"] == 33


def test_eth1_group_count(real_capture):
    info = _parse_igmp6_text(real_capture)
    assert len(info["eth1"]["groups"]) == 4


def test_addresses_decode_to_compressed_form(real_capture):
    info = _parse_igmp6_text(real_capture)
    eth1_addrs = [g["address"] for g in info["eth1"]["groups"]]
    assert eth1_addrs == [
        "ff02::1:ff00:b3",
        "ff02::1:ff00:101",
        "ff02::1",
        "ff01::1",
    ]


def test_solicited_node_refcounts(real_capture):
    """The real-world detail: two eth1 addresses end in 00:b3, so that
    solicited-node group carries refcount 2."""
    info = _parse_igmp6_text(real_capture)
    by_addr = {g["address"]: g for g in info["eth1"]["groups"]}
    assert by_addr["ff02::1:ff00:b3"]["users"] == 2
    assert by_addr["ff02::1:ff00:101"]["users"] == 1


def test_flags_preserved_verbatim(real_capture):
    info = _parse_igmp6_text(real_capture)
    by_addr = {g["address"]: g for g in info["eth1"]["groups"]}
    assert by_addr["ff02::1"]["flags"] == "0000000C"
    assert by_addr["ff02::1:ff00:b3"]["flags"] == "00000004"


def test_loopback_groups(real_capture):
    info = _parse_igmp6_text(real_capture)
    lo_addrs = [g["address"] for g in info["lo"]["groups"]]
    assert lo_addrs == ["ff02::1", "ff01::1"]


# ---------------------------------------------------------------------------
# Parser guards — these inputs are deliberately synthetic and labeled as
# such: they test the malformed-line skip path, not the real-world format.
# ---------------------------------------------------------------------------

def test_empty_input():
    assert _parse_igmp6_text("") == {}


def test_malformed_lines_skipped(real_capture):
    polluted = real_capture + "\nnot a real line\n12 short\n"
    info = _parse_igmp6_text(polluted)
    # The real content still parses; the junk is skipped.
    assert set(info.keys()) == {"lo", "eth0", "eth1"}
    assert len(info["eth1"]["groups"]) == 4


def test_bad_hex_address_skipped(real_capture):
    polluted = (
        real_capture
        + "9    ethX            zzzz0000000000000000000000000001     1 00000004 0\n"
    )
    info = _parse_igmp6_text(polluted)
    assert "ethX" not in info


# ---------------------------------------------------------------------------
# parse_proc_net_igmp6 — graceful degradation on hosts without IPv6
# ---------------------------------------------------------------------------

def test_missing_proc_file_returns_empty(monkeypatch):
    """The sandbox this suite first ran in has IPv6 disabled at the kernel
    level — /proc/net/igmp6 does not exist. That environment is itself a
    legitimate test case: the parser must degrade to {} rather than raise."""
    import mcast_tools.common as common

    monkeypatch.setattr(
        common, "_IGMP6_PROC_PATH", Path("/proc/net/igmp6-does-not-exist")
    )
    assert parse_proc_net_igmp6() == {}


# ---------------------------------------------------------------------------
# MLD sysctl helpers
# ---------------------------------------------------------------------------

def test_mld_force_path():
    assert str(mld_force_path("eth1")) == (
        "/proc/sys/net/ipv6/conf/eth1/force_mld_version"
    )


def test_read_force_mld_missing_returns_none():
    # No IPv6 in this kernel — the path doesn't exist. Must return None,
    # mirroring read_force_igmp_version's contract.
    assert read_force_mld_version("definitely-not-an-iface") is None


def test_write_force_mld_rejects_bad_version():
    with pytest.raises(ValueError, match="Invalid MLD version"):
        write_force_mld_version("eth1", 3)


def test_write_force_mld_missing_returns_false():
    assert write_force_mld_version("definitely-not-an-iface", 2) is False


def test_mld_roundtrip_via_tmpfile(tmp_path, monkeypatch):
    """Read/write against a real file (tmp), exercising the same code path
    the /proc write takes."""
    import mcast_tools.common as common

    fake = tmp_path / "force_mld_version"
    fake.write_text("0\n")
    monkeypatch.setattr(common, "mld_force_path", lambda iface: fake)
    assert common.read_force_mld_version("eth1") == 0
    assert common.write_force_mld_version("eth1", 1) is True
    assert common.read_force_mld_version("eth1") == 1
