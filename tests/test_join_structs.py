"""Byte-layout tests for the IPv6 multicast join structures.

These structures are handed to the kernel via setsockopt, so the layout is
ABI, not style. Offsets below come from the Linux UAPI headers
(include/uapi/linux/in.h and in6.h) for x86_64:

  struct ipv6_mreq {                         // 20 bytes
      struct in6_addr ipv6mr_multiaddr;      // offset 0,  16 bytes
      int             ipv6mr_ifindex;        // offset 16,  4 bytes (native)
  };

  struct group_source_req {                  // 264 bytes
      __u32 gsr_interface;                   // offset 0,   4 bytes (native)
      //    4 bytes padding                  // offset 4   (storage is 8-aligned)
      struct sockaddr_storage gsr_group;     // offset 8,   128 bytes
      struct sockaddr_storage gsr_source;    // offset 136, 128 bytes
  };

  struct sockaddr_in6 (within each storage):
      sa_family_t sin6_family;               // +0,  2 bytes (native)
      __be16      sin6_port;                 // +2,  2 bytes (network order)
      __be32      sin6_flowinfo;             // +4,  4 bytes (network order)
      struct in6_addr sin6_addr;             // +8,  16 bytes
      __u32       sin6_scope_id;             // +24, 4 bytes (native)
      //          zero padding to 128
"""
import ipaddress
import socket
import struct

import pytest

from mcast_tools.common import (
    GROUP_SOURCE_REQ_SIZE,
    MCAST_JOIN_SOURCE_GROUP,
    pack_group_source_req,
    pack_ipv6_mreq,
)

GROUP = ipaddress.IPv6Address("ff3e::8000:1")
SOURCE = ipaddress.IPv6Address("2001:db8:60:60::101")


# ---------------------------------------------------------------------------
# pack_ipv6_mreq
# ---------------------------------------------------------------------------

def test_ipv6_mreq_length():
    assert len(pack_ipv6_mreq(GROUP, ifindex=33)) == 20


def test_ipv6_mreq_address_bytes():
    buf = pack_ipv6_mreq(GROUP, ifindex=33)
    assert buf[0:16] == GROUP.packed


def test_ipv6_mreq_ifindex():
    buf = pack_ipv6_mreq(GROUP, ifindex=33)
    assert struct.unpack("=i", buf[16:20])[0] == 33


def test_ipv6_mreq_ifindex_zero_means_any():
    buf = pack_ipv6_mreq(GROUP, ifindex=0)
    assert struct.unpack("=i", buf[16:20])[0] == 0


# ---------------------------------------------------------------------------
# pack_group_source_req
# ---------------------------------------------------------------------------

def test_gsr_total_length():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    assert len(buf) == 264
    assert GROUP_SOURCE_REQ_SIZE == 264


def test_gsr_interface_index():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    assert struct.unpack("=I", buf[0:4])[0] == 33


def test_gsr_alignment_padding_is_zero():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    assert buf[4:8] == b"\x00" * 4


@pytest.mark.parametrize("offset", [8, 136])
def test_gsr_family_fields(offset):
    buf = pack_group_source_req(33, GROUP, SOURCE)
    assert buf[offset : offset + 2] == struct.pack("=H", socket.AF_INET6)


def test_gsr_group_address_bytes():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    # group storage at 8, sin6_addr at +8 within it
    assert buf[16:32] == GROUP.packed


def test_gsr_source_address_bytes():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    # source storage at 136, sin6_addr at +8 within it
    assert buf[144:160] == SOURCE.packed


def test_gsr_port_and_flowinfo_zero():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    for base in (8, 136):
        assert buf[base + 2 : base + 8] == b"\x00" * 6


def test_gsr_scope_id_in_group_sockaddr():
    buf = pack_group_source_req(33, GROUP, SOURCE, group_scope_id=33)
    assert struct.unpack("=I", buf[32:36])[0] == 33
    # source scope_id stays zero
    assert struct.unpack("=I", buf[160:164])[0] == 0


def test_gsr_storage_tails_are_zero():
    buf = pack_group_source_req(33, GROUP, SOURCE)
    # Beyond sockaddr_in6's 28 bytes, each 128-byte storage must be zero.
    assert buf[8 + 28 : 136] == b"\x00" * 100
    assert buf[136 + 28 : 264] == b"\x00" * 100


def test_mcast_join_source_group_constant():
    # Linux include/uapi/linux/in.h: MCAST_JOIN_SOURCE_GROUP = 46.
    # Python's socket module doesn't expose it on all builds; ours must
    # resolve to the kernel value either way.
    assert MCAST_JOIN_SOURCE_GROUP == 46
