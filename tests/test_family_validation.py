"""Tests for family-aware group/source validation and IPv6 classification.

IPv4 behavior must be byte-for-byte unchanged from v0.1.0 — those cases are
locked in here as regression guards. IPv6 cases cover RFC 4291 scope/flags
classification, RFC 4607 SSM range detection, and zone-id (%iface) handling.
"""
import ipaddress

import pytest

from mcast_tools.common import (
    classify_multicast_group,
    is_ssm_group,
    split_scope,
    validate_multicast_group,
    validate_source,
)


# ---------------------------------------------------------------------------
# validate_multicast_group — IPv4 regression guards (v0.1.0 behavior)
# ---------------------------------------------------------------------------

def test_v4_group_valid():
    addr = validate_multicast_group("239.0.10.101")
    assert isinstance(addr, ipaddress.IPv4Address)
    assert str(addr) == "239.0.10.101"


def test_v4_group_not_multicast():
    with pytest.raises(ValueError, match="not a multicast address"):
        validate_multicast_group("10.1.1.1")


def test_v4_garbage_rejected():
    with pytest.raises(ValueError, match="not a valid IP address"):
        validate_multicast_group("not-an-address")


# ---------------------------------------------------------------------------
# validate_multicast_group — IPv6 (new in v0.2.0)
# ---------------------------------------------------------------------------

def test_v6_group_valid():
    addr = validate_multicast_group("ff05::1")
    assert isinstance(addr, ipaddress.IPv6Address)
    assert str(addr) == "ff05::1"


def test_v6_group_with_zone():
    addr = validate_multicast_group("ff02::42%eth1")
    assert isinstance(addr, ipaddress.IPv6Address)
    assert addr.scope_id == "eth1"


def test_v6_unicast_rejected():
    with pytest.raises(ValueError, match="ff00::/8"):
        validate_multicast_group("2001:db8::1")


def test_v6_loopback_rejected():
    with pytest.raises(ValueError, match="not a multicast address"):
        validate_multicast_group("::1")


# ---------------------------------------------------------------------------
# split_scope
# ---------------------------------------------------------------------------

def test_split_scope_with_zone():
    scoped = ipaddress.IPv6Address("ff02::1%eth1")
    unscoped, zone = split_scope(scoped)
    assert str(unscoped) == "ff02::1"
    assert unscoped.scope_id is None
    assert zone == "eth1"


def test_split_scope_without_zone():
    addr = ipaddress.IPv6Address("ff0e::1")
    unscoped, zone = split_scope(addr)
    assert unscoped == addr
    assert zone is None


# ---------------------------------------------------------------------------
# classify_multicast_group — IPv4 regression guards (v0.1.0 behavior)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "group,expected",
    [
        ("224.0.0.5", "link-local (not routed)"),
        ("232.1.1.1", "SSM (source-specific)"),
        ("233.252.0.1", "GLOP"),
        ("239.0.10.101", "admin-scoped"),
        ("225.1.1.1", "any-source multicast"),
    ],
)
def test_v4_classification_unchanged(group, expected):
    assert classify_multicast_group(ipaddress.IPv4Address(group)) == expected


# ---------------------------------------------------------------------------
# classify_multicast_group — IPv6 (new in v0.2.0)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "group,expected",
    [
        # Well-known (flags=0) across scopes
        ("ff02::1", "well-known, link-local scope (not routed)"),
        ("ff02::d", "well-known, link-local scope (not routed)"),
        ("ff01::1", "well-known, interface-local scope (not routed)"),
        ("ff05::1:3", "well-known, site-local scope"),
        ("ff0e::1", "well-known, global scope"),
        # Transient (flags=1)
        ("ff15::abcd", "transient, site-local scope"),
        ("ff1e::1234", "transient, global scope"),
        # SSM (flags=3) across scopes
        ("ff3e::8000:1", "SSM (source-specific), global scope"),
        ("ff32::1", "SSM (source-specific), link-local scope (not routed)"),
        ("ff35::1", "SSM (source-specific), site-local scope"),
        # Embedded-RP (flags=7)
        ("ff7e:140:2001:db8::1", "embedded-RP, global scope"),
        # Solicited-node — from the real eth1 capture on host-ubuntu rev1.4
        ("ff02::1:ff00:b3", "solicited-node, link-local scope (not routed)"),
        ("ff02::1:ff00:101", "solicited-node, link-local scope (not routed)"),
        # Organization-local scope
        ("ff08::5", "well-known, organization-local scope"),
    ],
)
def test_v6_classification(group, expected):
    assert classify_multicast_group(ipaddress.IPv6Address(group)) == expected


def test_v6_classification_handles_scoped_address():
    scoped = ipaddress.IPv6Address("ff02::1%eth1")
    assert classify_multicast_group(scoped) == (
        "well-known, link-local scope (not routed)"
    )


# ---------------------------------------------------------------------------
# is_ssm_group
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "group,expected",
    [
        # IPv4 — v0.1.0 behavior unchanged
        ("232.1.1.1", True),
        ("239.0.10.101", False),
        # IPv6 — flags nibble == 3 (P=1, T=1) per RFC 4607
        ("ff3e::8000:1", True),
        ("ff32::1", True),
        ("ff02::1", False),
        ("ff7e::1", False),  # embedded-RP (flags=7) is NOT the SSM range
    ],
)
def test_is_ssm_group(group, expected):
    assert is_ssm_group(ipaddress.ip_address(group)) is expected


# ---------------------------------------------------------------------------
# validate_source — now family-aware relative to the group
# ---------------------------------------------------------------------------

V4_GROUP = ipaddress.IPv4Address("232.1.1.1")
V6_GROUP = ipaddress.IPv6Address("ff3e::8000:1")


def test_source_v4_for_v4_group():
    addr = validate_source("10.1.1.1", V4_GROUP)
    assert isinstance(addr, ipaddress.IPv4Address)


def test_source_v6_for_v6_group():
    addr = validate_source("2001:db8::5", V6_GROUP)
    assert isinstance(addr, ipaddress.IPv6Address)


def test_source_cross_family_v4_source_v6_group():
    with pytest.raises(ValueError, match="address family"):
        validate_source("10.1.1.1", V6_GROUP)


def test_source_cross_family_v6_source_v4_group():
    with pytest.raises(ValueError, match="address family"):
        validate_source("2001:db8::5", V4_GROUP)


def test_source_multicast_rejected_v4():
    with pytest.raises(ValueError, match="must be unicast"):
        validate_source("239.1.1.1", V4_GROUP)


def test_source_multicast_rejected_v6():
    with pytest.raises(ValueError, match="must be unicast"):
        validate_source("ff05::1", V6_GROUP)


def test_source_zone_rejected():
    with pytest.raises(ValueError, match="zone"):
        validate_source("fe80::1%eth1", V6_GROUP)


def test_source_garbage_rejected():
    with pytest.raises(ValueError, match="not a valid IP address"):
        validate_source("garbage", V4_GROUP)
