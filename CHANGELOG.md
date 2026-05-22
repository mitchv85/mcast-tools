# Changelog

All notable changes to mcast-tools are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-22

Initial release. Three CLIs replacing the lab's previous `iperf` usage with
something purpose-built for teaching multicast.

### Added

- **`mcast-send`** — IPv4 multicast sender with live `rich` dashboard.
  - Positional args: `<group> [duration] [ttl]` (duration default 600s, ttl
    default 100) plus equivalent `--duration` / `--ttl` flags.
  - `--rate` accepts both pps and bps units (`25pps`, `1Mbps`, `100kbps`).
  - `--dscp` accepts numeric (0-63) or symbolic names (`ef`, `af41`, `cs5`,
    etc.) and is set via `IP_TOS` on the socket.
  - `--interface` overrides the egress interface via `IP_MULTICAST_IF`.
  - `--size` configures the datagram size (header + payload).
  - `--no-loopback` disables `IP_MULTICAST_LOOP`.
  - `--quiet` / `--json` modes for automation.
  - Self-correcting deadline-based packet pacing — won't burst-catch-up after
    sleep contention.

- **`mcast-receive`** — IPv4 multicast receiver with live `rich` dashboard.
  - Positional args: `<group> [source] [igmp_version]` plus equivalent flags.
  - ASM (`(*,G)`) join via `IP_ADD_MEMBERSHIP`, SSM (`(S,G)`) join via
    `IP_ADD_SOURCE_MEMBERSHIP`.
  - Forces IGMP version via `/proc/sys/net/ipv4/conf/<iface>/force_igmp_version`,
    saves the prior value, and restores it on exit.
  - SSM requires IGMPv3 — refuses `--source` with v1/v2 and explains why.
  - Per-packet received TTL and TOS captured via `recvmsg` ancillary data
    (`IP_RECVTTL` / `IP_RECVTOS`).
  - Hop-count display derived from sender-stamped `orig_ttl` minus received TTL.
  - DSCP remark detection by comparing `orig_dscp` with the observed TOS byte.
  - Per-sender sequence tracking: accurate loss / duplicate / reorder
    counters that don't get confused by sender restarts or multiple senders.
  - Sender restart detection via random `sender_id` per invocation.
  - Stall detection with configurable `--stall-timeout` (default 3s) and a
    bounded gap-event log shown in the dashboard.
  - Foreign-packet counter for UDP traffic on the group that isn't from
    `mcast-tools` (no `MCAS` magic).
  - `--quiet` / `--json` / `--duration` modes for automation.

- **`mcast-status`** — pretty-prints current IPv4 multicast memberships from
  `/proc/net/igmp` using `rich`. `--all` includes kernel-default groups,
  `--interface` filters to one.

- **32-byte packet header** (`!IIQQIHBB`, big-endian) with magic `0x4D434153`
  (`"MCAS"`), protocol version, sequence, monotonic nanosecond timestamp,
  random per-invocation sender ID, payload length, original TTL, and
  original DSCP. Padded to the configured datagram size with `0xA5`.

- **Destination UDP port** fixed at `19779` (`0x4D43` = `"MC"`) for easy
  filtering in packet captures.

### Limitations (deliberately out of scope for v0.1)

- IPv6 / MLD (planned for a future release).
- PCAP integration on the receiver side.
- Bidirectional / round-trip-time mode.
