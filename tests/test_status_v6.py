"""Tests for mcast-status's IPv6 table rows.

The baseline igmp6 state comes from the same REAL host-ubuntu rev1.4
capture used in test_mld_and_igmp6.py. A pleasing property of that
capture: every group on it is kernel-default noise (all-nodes ff02::1 /
ff01::1 and solicited-node ff02::1:ff00:xx) — so the default filtered
view of a freshly-booted host is *empty*, which is exactly the signal
"no userspace joins are active."

The joined-group case constructs a parsed-dict entry directly (an ff05::
join as mcast-receive would create) rather than synthesizing raw
/proc/net/igmp6 text — the raw-format parse path is only ever tested
against real bytes.
"""
from pathlib import Path

import pytest

from mcast_tools.common import _parse_igmp6_text
from mcast_tools.status import _is_v6_noise, v6_rows

FIXTURE = Path(__file__).parent / "fixtures" / "igmp6_host_ubuntu_2404.txt"


@pytest.fixture
def baseline():
    return _parse_igmp6_text(FIXTURE.read_text())


# ---------------------------------------------------------------------------
# Noise detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "addr,noise",
    [
        ("ff02::1", True),            # all-nodes, link-local
        ("ff01::1", True),            # all-nodes, interface-local
        ("ff02::1:ff00:b3", True),    # solicited-node (real capture)
        ("ff02::1:ff12:3456", True),  # solicited-node, any low 24 bits
        ("ff02::2", False),           # all-routers — a real signal
        ("ff05::1:3", False),         # DHCPv6 site-scope
        ("ff3e::8000:1", False),      # SSM join
        ("ff02::d", False),           # all-PIM-routers
    ],
)
def test_is_v6_noise(addr, noise):
    assert _is_v6_noise(addr) is noise


# ---------------------------------------------------------------------------
# v6_rows — against the real baseline capture
# ---------------------------------------------------------------------------

def test_baseline_default_view_is_empty(baseline):
    # Everything on a freshly-booted host is kernel noise.
    assert v6_rows(baseline, show_all=False, iface_filter=None) == []


def test_baseline_show_all(baseline):
    rows = v6_rows(baseline, show_all=True, iface_filter=None)
    # lo is skipped; eth0 has 2 groups, eth1 has 4.
    ifaces = [r[0] for r in rows]
    assert ifaces.count("eth0") == 2
    assert ifaces.count("eth1") == 4
    assert "lo" not in ifaces


def test_baseline_iface_filter(baseline):
    rows = v6_rows(baseline, show_all=True, iface_filter="eth1")
    assert {r[0] for r in rows} == {"eth1"}
    assert len(rows) == 4


def test_row_shape_and_classification(baseline):
    rows = v6_rows(baseline, show_all=True, iface_filter="eth1")
    by_addr = {r[1]: r for r in rows}
    iface, addr, users, clazz = by_addr["ff02::1:ff00:b3"]
    assert iface == "eth1"
    assert users == 2  # the real-capture refcount-2 detail
    assert clazz == "solicited-node, link-local scope (not routed)"
    assert by_addr["ff02::1"][3] == "well-known, link-local scope (not routed)"


def test_joined_group_surfaces_in_default_view(baseline):
    # Simulate the state after `mcast-receive ff05::1:3 -i eth1` — append
    # the membership to the parsed structure the way the kernel would.
    baseline["eth1"]["groups"].append(
        {"address": "ff05::1:3", "users": 1, "flags": "00000004"}
    )
    rows = v6_rows(baseline, show_all=False, iface_filter=None)
    assert rows == [
        ("eth1", "ff05::1:3", 1, "well-known, site-local scope"),
    ]
