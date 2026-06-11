"""Tests for mcast-send's --source flag (bind the outgoing source address).

Born from real lab evidence (2026-06-11): a sender host with two
same-prefix IPv6 globals had the kernel's RFC 6724 source selection pick
a different address across runs — `::101` one day, the EUI-64
`…:1ff:fe00:a2` the next — silently breaking any SSM receiver filtering
on the other one. Binding the source takes selection out of the
conversation entirely; the rules only apply to unbound sockets.

Validation reuses common.validate_source — the same family-matching and
zone-rejection the receiver's SSM source already gets — so the
cross-family errors here are the receiver's errors verbatim.

The IPv4 bind tests run LIVE against this host's real addresses (bind to
the primary succeeds; bind to TEST-NET-1 raises EADDRNOTAVAIL). The IPv6
bind cannot run here (sandbox kernel has IPv6 disabled — socket creation
fails before bind); it is exercised at the validation layer and verified
in the lab before the v0.2.1 tag.
"""
import errno
import socket

import pytest

from mcast_tools import sender
from mcast_tools.sender import build_parser, setup_sender_socket


def _local_ipv4() -> str:
    """This host's primary outbound IPv4 — a real, assigned address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no traffic sent for UDP connect
        return s.getsockname()[0]
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Parser surface
# ---------------------------------------------------------------------------

def test_source_flag_parses():
    args = build_parser().parse_args(["239.0.10.101", "--source", "10.1.1.1"])
    assert args.source == "10.1.1.1"


def test_source_short_flag():
    args = build_parser().parse_args(["ff05::1", "-S", "2001:db8::5"])
    assert args.source == "2001:db8::5"


def test_source_default_none():
    assert build_parser().parse_args(["239.0.10.101"]).source is None


# ---------------------------------------------------------------------------
# main() validation — pre-socket, sandbox-safe
# ---------------------------------------------------------------------------

def test_v4_group_rejects_v6_source(capsys):
    rc = sender.main(["239.0.10.101", "--source", "2001:db8::5"])
    assert rc == 2
    out = capsys.readouterr().out
    assert "family" in out


def test_v6_group_rejects_v4_source(capsys):
    rc = sender.main(["ff05::1", "--source", "10.1.1.1"])
    assert rc == 2
    assert "family" in capsys.readouterr().out


def test_zoned_source_rejected(capsys):
    rc = sender.main(["ff05::1", "--source", "fe80::1%eth1"])
    assert rc == 2
    assert "%zone" in capsys.readouterr().out


def test_multicast_source_rejected(capsys):
    rc = sender.main(["239.0.10.101", "--source", "239.1.1.1"])
    assert rc == 2
    assert "unicast" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# IPv4 bind — LIVE against this host
# ---------------------------------------------------------------------------

def test_v4_bind_to_real_address():
    addr = _local_ipv4()
    sock = setup_sender_socket(
        group="239.9.9.9",
        ttl=10,
        dscp=0,
        interface_ip=None,
        enable_loopback=True,
        source=addr,
    )
    try:
        assert sock.getsockname()[0] == addr
    finally:
        sock.close()


def test_v4_bind_unassigned_raises_eaddrnotavail():
    with pytest.raises(OSError) as exc:
        setup_sender_socket(
            group="239.9.9.9",
            ttl=10,
            dscp=0,
            interface_ip=None,
            enable_loopback=True,
            source="192.0.2.99",  # TEST-NET-1, never assigned here
        )
    assert exc.value.errno == errno.EADDRNOTAVAIL


def test_unbound_default_unchanged():
    # v0.2.0 regression guard: no source → no bind → wildcard local addr.
    sock = setup_sender_socket(
        group="239.9.9.9",
        ttl=10,
        dscp=0,
        interface_ip=None,
        enable_loopback=True,
        source=None,
    )
    try:
        assert sock.getsockname()[0] == "0.0.0.0"
    finally:
        sock.close()


def test_main_friendly_error_on_unassigned_source(capsys):
    rc = sender.main(
        ["239.9.9.9", "--source", "192.0.2.99", "--duration", "1", "--quiet"]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "isn't assigned" in out
