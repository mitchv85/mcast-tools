"""Tests for mcast-send's IPv6 pure helpers.

The addr_info JSON below is a REAL capture: `ip -j -6 addr show dev eth1`
from a host-ubuntu rev1.4 container (Ubuntu 24.04.4), taken 2026-06-11.
eth1 carries one SLAAC global, one static global, and the fe80 link-local
— the picker must prefer global scope and fall back to link scope.
"""
import ipaddress
import json

import pytest

from mcast_tools.common import needs_explicit_interface, v6_scope_nibble
from mcast_tools.sender import _pick_v6_addr, make_send_dest

# Real capture — ip -j -6 addr show dev eth1 (host-ubuntu rev1.4, 2026-06-11)
REAL_ETH1_JSON = (
    '[{"ifindex":33,"link_index":32,"ifname":"eth1","flags":["BROADCAST",'
    '"MULTICAST","UP","LOWER_UP"],"mtu":9500,"qdisc":"noqueue","operstate":'
    '"UP","group":"default","link_netnsid":1,"altnames":'
    '["clab-o-8935e0b28b5efd2b"],"addr_info":[{"family":"inet6","local":'
    '"2001:db8:60:60:201:1ff:fe00:b3","prefixlen":64,"scope":"global",'
    '"dynamic":true,"mngtmpaddr":true,"valid_life_time":2591997,'
    '"preferred_life_time":604797},{"family":"inet6","local":'
    '"2001:db8:60:60::101","prefixlen":64,"scope":"global",'
    '"valid_life_time":4294967295,"preferred_life_time":4294967295},'
    '{"family":"inet6","local":"fe80::201:1ff:fe00:b3","prefixlen":64,'
    '"scope":"link","valid_life_time":4294967295,'
    '"preferred_life_time":4294967295}]}]'
)


# ---------------------------------------------------------------------------
# _pick_v6_addr — prefer global scope, fall back to link
# ---------------------------------------------------------------------------

def test_pick_prefers_global_scope():
    addr_info = json.loads(REAL_ETH1_JSON)[0]["addr_info"]
    # First global entry wins (the SLAAC address in the real capture).
    assert _pick_v6_addr(addr_info) == "2001:db8:60:60:201:1ff:fe00:b3"


def test_pick_falls_back_to_link_local():
    addr_info = json.loads(REAL_ETH1_JSON)[0]["addr_info"]
    link_only = [a for a in addr_info if a.get("scope") == "link"]
    assert _pick_v6_addr(link_only) == "fe80::201:1ff:fe00:b3"


def test_pick_ignores_inet4_entries():
    addr_info = [
        {"family": "inet", "local": "10.0.0.1", "scope": "global"},
    ]
    assert _pick_v6_addr(addr_info) is None


def test_pick_empty():
    assert _pick_v6_addr([]) is None


# ---------------------------------------------------------------------------
# v6_scope_nibble / needs_explicit_interface
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "group,nibble",
    [
        ("ff01::1", 0x1),
        ("ff02::1", 0x2),
        ("ff05::1:3", 0x5),
        ("ff0e::1", 0xE),
        ("ff3e::8000:1", 0xE),
    ],
)
def test_v6_scope_nibble(group, nibble):
    assert v6_scope_nibble(ipaddress.IPv6Address(group)) == nibble


def test_scope_nibble_handles_zone():
    assert v6_scope_nibble(ipaddress.IPv6Address("ff02::1%eth1")) == 0x2


@pytest.mark.parametrize(
    "group,needed",
    [
        ("ff01::1", True),   # interface-local
        ("ff02::42", True),  # link-local
        ("ff05::1", False),  # site-local — routable, route table can pick
        ("ff0e::1", False),  # global
        ("ff3e::8000:1", False),
    ],
)
def test_needs_explicit_interface(group, needed):
    assert needs_explicit_interface(ipaddress.IPv6Address(group)) is needed


# ---------------------------------------------------------------------------
# make_send_dest — family-appropriate sendto destination
# ---------------------------------------------------------------------------

def test_dest_v4_is_two_tuple():
    dest = make_send_dest(ipaddress.IPv4Address("239.0.10.101"), 19779, None)
    assert dest == ("239.0.10.101", 19779)


def test_dest_v6_is_four_tuple_with_ifindex():
    dest = make_send_dest(ipaddress.IPv6Address("ff02::42"), 19779, 33)
    assert dest == ("ff02::42", 19779, 0, 33)


def test_dest_v6_without_ifindex_uses_zero():
    dest = make_send_dest(ipaddress.IPv6Address("ff0e::1"), 19779, None)
    assert dest == ("ff0e::1", 19779, 0, 0)


def test_dest_v6_strips_zone_text():
    # The zone rides in the scope_id slot, never in the host string.
    dest = make_send_dest(ipaddress.IPv6Address("ff02::42%eth1"), 19779, 33)
    assert dest == ("ff02::42", 19779, 0, 33)
