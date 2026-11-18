"""Windows compatibility of mcast-receive, tested by simulating Windows.

There's no Windows host in CI, so these tests flip the receiver's platform
flags (IS_WINDOWS, HAVE_RECVMSG, and sys.platform for the shared helpers) and
check the calls made at the OS boundary: what setup does to the socket before
and after bind(), the bytes and option numbers of each join, and which
receive call the loop uses. Every Windows expectation comes with a Linux
counterpart that pins today's behaviour.

Windows facts encoded here, from the Winsock headers (ws2ipdef.h) and docs:
  * bind() to a multicast address fails with WSAEADDRNOTAVAIL (WinError 10049)
  * IP_ADD_SOURCE_MEMBERSHIP = 15 (Linux: 39); MCAST_JOIN_SOURCE_GROUP = 45
  * struct ip_mreq_source is {multiaddr, sourceaddr, interface}; Linux puts
    the interface second
  * Python on Windows has no socket.recvmsg
"""
from __future__ import annotations

import ipaddress
import json
import signal
import socket
import subprocess
import sys
import threading

import pytest
from rich.console import Console

from mcast_tools import common, receiver, sender
from mcast_tools.common import make_packet, pack_group_source_req, pack_ipv6_mreq

aton = socket.inet_aton
PORT = receiver.MCAST_PORT


class RecordingSocket:
    """Stands in for socket.socket and records what setup does to it."""

    def __init__(self, *args, **kwargs):
        self.calls: list[tuple] = []

    def setsockopt(self, level, opt, value):
        self.calls.append(("setsockopt", level, opt, value))

    def bind(self, addr):
        self.calls.append(("bind", addr))

    def close(self):
        pass


def _setup_v4(monkeypatch, *, windows, group="239.0.0.1", source=None, iface=None):
    monkeypatch.setattr(receiver, "IS_WINDOWS", windows)
    monkeypatch.setattr(receiver.socket, "socket", RecordingSocket)
    return receiver.setup_receiver_socket(group, source, iface)


def _setup_v6(monkeypatch, *, windows, group, source=None, ifindex=None):
    monkeypatch.setattr(receiver, "IS_WINDOWS", windows)
    monkeypatch.setattr(receiver.socket, "socket", RecordingSocket)
    return receiver.setup_receiver_socket_v6(ipaddress.IPv6Address(group), source, ifindex)


def _split_at_bind(calls):
    binds = [i for i, c in enumerate(calls) if c[0] == "bind"]
    assert len(binds) == 1, calls
    return calls[: binds[0]], calls[binds[0]][1], calls[binds[0] + 1 :]


# ---------------------------------------------------------------------------
# IPv4 socket setup
# ---------------------------------------------------------------------------

def test_v4_windows_binds_wildcard_and_sets_only_socket_level_options(monkeypatch):
    sock = _setup_v4(monkeypatch, windows=True)
    before, bound, after = _split_at_bind(sock.calls)
    assert bound == ("0.0.0.0", PORT)  # binding 239.0.0.1 is WinError 10049
    # Winsock may defer checking IP-level options set before bind() and fail
    # the bind itself, so only SO_REUSEADDR (and friends) may come first.
    assert all(c[1] == socket.SOL_SOCKET for c in before)
    assert after == [
        ("setsockopt", socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
         aton("239.0.0.1") + aton("0.0.0.0")),
    ]


def test_v4_linux_keeps_group_bind_and_ancillary_options(monkeypatch):
    sock = _setup_v4(monkeypatch, windows=False)
    before, bound, after = _split_at_bind(sock.calls)
    assert bound == ("239.0.0.1", PORT)
    ip_opts = [c[2] for c in before if c[1] == socket.IPPROTO_IP]
    assert ip_opts == [receiver.IP_MULTICAST_ALL, receiver.IP_RECVTTL, receiver.IP_RECVTOS]
    assert after == [
        ("setsockopt", socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
         aton("239.0.0.1") + aton("0.0.0.0")),
    ]


# ---------------------------------------------------------------------------
# IPv4 SSM: option number and struct ip_mreq_source field order
# ---------------------------------------------------------------------------

G, SRC, IFACE = "232.1.1.1", "10.1.1.1", "192.0.2.10"


def test_v4_ssm_windows_layout_and_option(monkeypatch):
    monkeypatch.delattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", raising=False)
    sock = _setup_v4(monkeypatch, windows=True, group=G, source=SRC, iface=IFACE)
    _, level, opt, mreq = sock.calls[-1]
    assert (level, opt) == (socket.IPPROTO_IP, 15)
    assert mreq == aton(G) + aton(SRC) + aton(IFACE)  # multiaddr, source, iface


def test_v4_ssm_linux_layout_and_py310_fallback(monkeypatch):
    # Python 3.10/3.11 don't export IP_ADD_SOURCE_MEMBERSHIP: this used to be
    # an AttributeError traceback on Linux too.
    monkeypatch.delattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    sock = _setup_v4(monkeypatch, windows=False, group=G, source=SRC, iface=IFACE)
    _, level, opt, mreq = sock.calls[-1]
    assert (level, opt) == (socket.IPPROTO_IP, 39)
    assert mreq == aton(G) + aton(IFACE) + aton(SRC)  # multiaddr, iface, source


def test_v4_ssm_prefers_pythons_constant(monkeypatch):
    monkeypatch.setattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", 12345, raising=False)
    sock = _setup_v4(monkeypatch, windows=False, group=G, source=SRC)
    assert sock.calls[-1][2] == 12345


def test_v4_ssm_unknown_platform_is_a_clean_oserror(monkeypatch):
    monkeypatch.delattr(socket, "IP_ADD_SOURCE_MEMBERSHIP", raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(OSError, match="IP_ADD_SOURCE_MEMBERSHIP"):
        _setup_v4(monkeypatch, windows=False, group=G, source=SRC)


# ---------------------------------------------------------------------------
# IPv6 socket setup
# ---------------------------------------------------------------------------

def test_v6_windows_binds_wildcard_and_joins_with_the_index(monkeypatch):
    sock = _setup_v6(monkeypatch, windows=True, group="ff3e::8000:1", ifindex=7)
    before, bound, after = _split_at_bind(sock.calls)
    assert bound == ("::", PORT, 0, 0)
    assert all(c[1] == socket.SOL_SOCKET for c in before)
    assert after == [
        ("setsockopt", socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
         pack_ipv6_mreq(ipaddress.IPv6Address("ff3e::8000:1"), 7)),
    ]


def test_v6_linux_keeps_group_bind_and_ancillary_options(monkeypatch):
    sock = _setup_v6(monkeypatch, windows=False, group="ff3e::8000:1", ifindex=7)
    before, bound, _after = _split_at_bind(sock.calls)
    assert bound == ("ff3e::8000:1", PORT, 0, 7)
    v6_opts = [c[2] for c in before if c[1] == socket.IPPROTO_IPV6]
    assert v6_opts == [
        receiver.IPV6_MULTICAST_ALL, receiver.IPV6_RECVHOPLIMIT, receiver.IPV6_RECVTCLASS,
    ]


def test_mcast_join_source_group_per_platform(monkeypatch):
    monkeypatch.delattr(socket, "MCAST_JOIN_SOURCE_GROUP", raising=False)
    assert common._mcast_join_source_group("win32") == 45  # 46 is the *leave* there
    assert common._mcast_join_source_group("linux") == 46


def test_v6_ssm_windows_uses_the_join_not_the_leave(monkeypatch):
    monkeypatch.delattr(socket, "MCAST_JOIN_SOURCE_GROUP", raising=False)
    monkeypatch.setattr(receiver, "MCAST_JOIN_SOURCE_GROUP",
                        common._mcast_join_source_group("win32"))
    sock = _setup_v6(monkeypatch, windows=True, group="ff3e::8000:1",
                     source="2001:db8::5", ifindex=7)
    _, level, opt, gsr = sock.calls[-1]
    assert (level, opt) == (socket.IPPROTO_IPV6, 45)
    assert gsr == pack_group_source_req(
        7, ipaddress.IPv6Address("ff3e::8000:1"),
        ipaddress.IPv6Address("2001:db8::5"), group_scope_id=7,
    )


# ---------------------------------------------------------------------------
# Receive loop without recvmsg
# ---------------------------------------------------------------------------

class RecvfromOnlySocket:
    """Like a socket from Python on Windows: recvfrom, but no recvmsg."""

    def __init__(self, datagrams, stop_event):
        self._datagrams = list(datagrams)
        self._stop = stop_event

    def settimeout(self, _timeout):
        pass

    def recvfrom(self, _bufsize):
        if self._datagrams:
            return self._datagrams.pop(0), ("192.0.2.1", PORT)
        self._stop.set()
        raise socket.timeout()


def test_recv_loop_falls_back_to_recvfrom(monkeypatch):
    monkeypatch.setattr(receiver, "HAVE_RECVMSG", False)
    stop = threading.Event()
    packets = [
        make_packet(seq=n, send_ns=n, sender_id=0xABCD, orig_ttl=64, orig_dscp=46,
                    datagram_size=64)
        for n in (1, 2, 3)
    ]
    stats = receiver.ReceiverStats()
    receiver.recv_loop(RecvfromOnlySocket(packets, stop), stats, stop,
                       stall_timeout=3.0, duration=0)
    assert stats.packets_recv == 3
    assert stats.packets_lost_total == 0
    assert stats.last_src_addr == "192.0.2.1"
    assert stats.last_orig_ttl == 64
    assert stats.last_recv_ttl is None  # not readable without recvmsg
    assert stats.last_recv_dscp is None


# ---------------------------------------------------------------------------
# Dashboard: say TTL/DSCP are unavailable instead of hiding the rows
# ---------------------------------------------------------------------------

def _dashboard_text(stats) -> str:
    console = Console(record=True, width=120)
    console.print(receiver.render_dashboard(
        group="239.0.0.1", group_class="test", source=None, join_type="(*,G) — ASM",
        interface="", iface_ip=None, requested_igmp=3, observed_igmp=None,
        stats=stats, stall_timeout=3.0, running=True,
    ))
    return console.export_text()


def _stats_from_a_sender():
    stats = receiver.ReceiverStats()
    stats.last_orig_ttl = 64
    stats.last_orig_dscp = 46
    return stats


def test_dashboard_marks_ttl_and_dscp_unavailable_without_recvmsg(monkeypatch):
    monkeypatch.setattr(receiver, "HAVE_RECVMSG", False)
    text = _dashboard_text(_stats_from_a_sender())
    assert "Received TTL:" in text
    assert "n/a on this platform (sender set 64)" in text
    assert "Received DSCP:" in text
    assert text.count("n/a on this platform") == 2


def test_dashboard_rows_unchanged_when_recvmsg_exists(monkeypatch):
    monkeypatch.setattr(receiver, "HAVE_RECVMSG", True)
    text = _dashboard_text(_stats_from_a_sender())
    assert "Received TTL:" not in text
    assert "n/a on this platform" not in text


def test_dashboard_version_row_on_windows_claims_no_request(monkeypatch):
    monkeypatch.setattr(receiver, "IS_WINDOWS", True)
    text = _dashboard_text(receiver.ReceiverStats())
    assert "OS setting (not forced on Windows)" in text
    assert "requested" not in text


def test_dashboard_version_row_on_linux_unchanged(monkeypatch):
    monkeypatch.setattr(receiver, "IS_WINDOWS", False)
    text = _dashboard_text(receiver.ReceiverStats())
    assert "v3 requested  (observed: unknown)" in text


# ---------------------------------------------------------------------------
# Interface index resolution (numeric IPv6 zones on Windows)
# ---------------------------------------------------------------------------

def _fake_interfaces(monkeypatch):
    by_index = {12: "ethernet_32770"}

    def if_indextoname(index):
        if index >= 2**32:
            raise OverflowError("index too large")
        if index not in by_index:
            raise OSError("no interface with this index")
        return by_index[index]

    def if_nametoindex(name):
        for index, n in by_index.items():
            if n == name:
                return index
        raise OSError("no interface with this name")

    monkeypatch.setattr(socket, "if_indextoname", if_indextoname)
    monkeypatch.setattr(socket, "if_nametoindex", if_nametoindex)


def test_resolve_ifindex_accepts_numeric_zones_on_windows(monkeypatch):
    _fake_interfaces(monkeypatch)
    monkeypatch.setattr(receiver, "IS_WINDOWS", True)
    assert receiver.resolve_ifindex("12") == 12
    assert receiver.resolve_ifindex("ethernet_32770") == 12
    for bad in ("99", "99999999999999999999", "Ethernet"):
        with pytest.raises(OSError):
            receiver.resolve_ifindex(bad)


def test_resolve_ifindex_rejects_out_of_range_numbers_cleanly(monkeypatch):
    _fake_interfaces(monkeypatch)
    monkeypatch.setattr(receiver, "IS_WINDOWS", True)

    def cpython310_indextoname(index):
        # 3.10 on Windows raises SystemError for 0xFFFFFFFF; main() only
        # catches OSError, so an index like that must never get this far.
        raise SystemError("error return without exception set")

    monkeypatch.setattr(socket, "if_indextoname", cpython310_indextoname)
    for bad in ("0", "4294967295", "9" * 5000):  # 5000 digits: int() refuses
        with pytest.raises(OSError):
            receiver.resolve_ifindex(bad)


def test_resolve_ifindex_linux_treats_numbers_as_names(monkeypatch):
    _fake_interfaces(monkeypatch)
    monkeypatch.setattr(receiver, "IS_WINDOWS", False)
    with pytest.raises(OSError):
        receiver.resolve_ifindex("12")  # unchanged: a name lookup
    assert receiver.resolve_ifindex("ethernet_32770") == 12


# ---------------------------------------------------------------------------
# No `ip` subprocess on Windows
# ---------------------------------------------------------------------------

def test_ip_helpers_skip_the_subprocess_on_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")

    def no_subprocess(*args, **kwargs):
        raise AssertionError(f"subprocess.run called: {args}")

    monkeypatch.setattr(subprocess, "run", no_subprocess)
    assert common.RouteInfo.for_destination("239.0.0.1") is None
    assert sender.get_interface_ip("Ethernet") is None
    assert sender.get_interface_ipv6("Ethernet") is None


# ---------------------------------------------------------------------------
# main(): exit status, version forcing and --interface on Windows
# ---------------------------------------------------------------------------

class DummySocket:
    def close(self):
        pass


@pytest.fixture
def stubbed_main(monkeypatch):
    """Run receiver.main() without real sockets, routes or signal handlers."""
    joins = []

    def fake_setup(**kwargs):
        joins.append(kwargs)
        return DummySocket()

    monkeypatch.setattr(receiver, "setup_receiver_socket", fake_setup)
    monkeypatch.setattr(receiver, "setup_receiver_socket_v6", fake_setup)
    monkeypatch.setattr(receiver.RouteInfo, "for_destination",
                        classmethod(lambda cls, dest: None))
    monkeypatch.setattr(receiver, "recv_loop", lambda **kwargs: None)
    monkeypatch.setattr(signal, "signal", lambda *args: None)
    return joins


def _run(capsys, argv):
    rc = receiver.main(argv)
    out = capsys.readouterr().out
    lines = out.strip().splitlines()
    summary = json.loads(lines[-1]) if lines and lines[-1].startswith("{") else None
    return rc, " ".join(out.split()), summary


def _as_windows(monkeypatch):
    """Windows mode for main(): the receiver's flag, plus the Windows result
    (None) of the shared `ip` helpers, which have their own test above.
    sys.platform stays real, so nothing imported while main() runs gets
    cached with Windows settings."""
    monkeypatch.setattr(receiver, "IS_WINDOWS", True)
    monkeypatch.setattr(sender, "get_interface_ip", lambda interface: None)
    monkeypatch.setattr(sender, "get_interface_ipv6", lambda interface: None)


def test_clean_run_exits_zero_without_an_error_field(stubbed_main, capsys):
    rc, _text, summary = _run(capsys, ["239.0.0.1", "--quiet", "--json"])
    assert rc == 0
    assert "error" not in summary


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_receive_thread_crash_is_not_reported_as_success(stubbed_main, monkeypatch, capsys):
    def boom(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(receiver, "recv_loop", boom)
    rc, text, summary = _run(capsys, ["239.0.0.1", "--quiet", "--json"])
    assert rc == 1
    assert "receive loop failed" in text
    assert summary["error"] == "RuntimeError('boom')"


def test_windows_explains_version_forcing_instead_of_using_proc(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)

    def no_proc(*args):
        raise AssertionError("Linux /proc helper called on Windows")

    monkeypatch.setattr(receiver, "read_force_igmp_version", no_proc)
    monkeypatch.setattr(receiver, "write_force_igmp_version", no_proc)
    rc, text, _ = _run(capsys, ["239.0.0.1", "--igmp-version", "2", "--quiet"])
    assert rc == 0
    assert "can't force the IGMP version on Windows" in text
    assert "Set-NetIPv4Protocol -IGMPVersion" in text
    assert "(IGMP version: OS setting)" in text


def test_windows_default_version_needs_no_warning(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    rc, text, _ = _run(capsys, ["239.0.0.1", "--quiet"])
    assert rc == 0
    assert "can't force" not in text


def test_windows_interface_name_is_reported_and_dropped(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    rc, text, summary = _run(
        capsys, ["239.0.0.1", "--interface", "Ethernet", "--quiet", "--json"]
    )
    assert rc == 0
    assert "can't look up interface names on Windows" in text
    assert summary["interface"] is None  # the join really used the default


# ---------------------------------------------------------------------------
# main(): IPv6 on Windows (zones, interface hints, MLD forcing)
# ---------------------------------------------------------------------------

def test_windows_v6_numeric_zone_joins_without_proc(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    _fake_interfaces(monkeypatch)

    def no_proc(*args):
        raise AssertionError("Linux /proc helper called on Windows")

    monkeypatch.setattr(receiver, "read_force_mld_version", no_proc)
    monkeypatch.setattr(receiver, "write_force_mld_version", no_proc)
    rc, text, _ = _run(capsys, ["ff02::42%12", "--mld-version", "1", "--quiet", "--json"])
    assert rc == 0
    assert stubbed_main[-1]["ifindex"] == 12  # the zone, as ipconfig shows it
    assert "can't force the MLD version on Windows" in text
    assert "Set-NetIPv6Protocol -MldVersion" in text
    assert "could not resolve" not in text  # display-only lookup, none on Windows


def test_windows_v6_named_zone_gets_the_index_hint(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    _fake_interfaces(monkeypatch)
    rc, text, _ = _run(capsys, ["ff02::42%Ethernet", "--quiet"])
    assert rc == 2
    assert "interface 'Ethernet' not found — on Windows, use the interface index" in text


def test_windows_link_local_without_zone_suggests_an_index(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    rc, text, _ = _run(capsys, ["ff02::42", "--quiet"])
    assert rc == 2
    assert "(ff02::42%12, the interface index ipconfig shows)" in text


def test_linux_link_local_without_zone_message_unchanged(stubbed_main, monkeypatch, capsys):
    monkeypatch.setattr(receiver, "IS_WINDOWS", False)
    rc, text, _ = _run(capsys, ["ff02::42", "--quiet"])
    assert rc == 2
    assert "Use a %zone (ff02::42%eth1) or --interface." in text


def test_windows_positional_version_counts_as_a_request(stubbed_main, monkeypatch, capsys):
    _as_windows(monkeypatch)
    rc, text, _ = _run(capsys, ["ff3e::8000:1", "2001:db8::5", "2", "--quiet"])
    assert rc == 0
    assert "can't force the MLD version on Windows" in text
