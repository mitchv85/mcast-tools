# Changelog

All notable changes to mcast-tools are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] — 2026-11-18

### Added

- **Windows support.** `mcast-receive` now runs natively on Windows
  alongside `mcast-send`: IPv4 and IPv6, ASM and SSM, verified on
  Windows 11 receiving from Linux senders. It used to fail at once with
  `[WinError 10049] The requested address is not valid in its context`,
  because it bound its socket to the group address, a Linux idiom that
  Winsock refuses. On Windows the receiver now binds the wildcard
  address, skips the Linux-only socket options, reads packets with
  `recvfrom` (Python has no `recvmsg` there), and packs SSM joins with
  Winsock's struct layout and option numbers. IPv6 zones and
  `--interface` take the interface index (`ff02::42%12`). See the
  Windows section of the [guide](docs/guide.md).

### Fixed

- **IPv4 SSM crashed on Python 3.10 and 3.11** with an `AttributeError`,
  because `socket.IP_ADD_SOURCE_MEMBERSHIP` only exists from Python 3.12.
  The platform's value is now used when Python doesn't provide it.
- **A crash in the receive thread was reported as success**: exit code 0
  and an all-zero JSON summary. It now prints the error and exits 1, and
  the JSON summary gains an `"error"` field.

### Changed

- **The README is now a short overview.** The full reference moved to
  [`docs/guide.md`](docs/guide.md), which adds a Windows section.
- **PyPI metadata** now lists Windows and Python 3.13.

### Known limitations on Windows

- No received TTL/DSCP readout (shown as `n/a on this platform`), no
  IGMP/MLD version forcing (a host-wide setting on Windows), no interface
  selection by name (IPv4 always uses the default interface; only the
  receiver takes an IPv6 interface index), and no sending to link-local
  IPv6 groups. `mcast-status` remains Linux-only. `mcast-send` on Windows
  has been verified over IPv4 only.

## [0.2.2] — 2026-06-11

### Fixed

- **Crash: `RuntimeError: deque mutated during iteration`** in
  `current_pps()` on both sender and receiver (present since v0.1.0).
  The worker thread's rate-sample appends raced the dashboard thread's
  sliding-window walk; any deque mutation invalidates live iterators.
  Rate samples are now guarded by a per-stats lock with snapshot-based
  reads. The bug required a process older than the 5-second rate window
  and was *most* likely at low packet rates (a stale-majority sample
  deque maximizes the walk length) — which is why simple default-rate
  runs hit it while stress runs often didn't.

## [0.2.1] — 2026-06-11

### Added

- **`mcast-send --source` / `-S`** — bind the outgoing source address,
  both families. Removes RFC 6724 source-address selection from the
  picture (the rules only apply to unbound sockets), making SSM (S,G)
  demos deterministic when an interface carries multiple candidate
  addresses (two same-prefix IPv6 globals; IPv4 secondaries/VIPs).
  Validation reuses the receiver's SSM source checks — family matching,
  %zone rejection — so `mcast-send G --source S` pairs naturally with
  `mcast-receive G --source S`. Friendly error when the address isn't
  assigned to the host. Dashboard shows a "Source: (bound)" row when
  given; JSON gains a `"source"` field (null when unbound). Found in the
  field during v0.2.0 lab verification, when the kernel sourced from a
  SLAAC EUI-64 address one run and a static global the next.

## [0.2.0] — 2026-06-11

IPv6 / MLD support across all three tools — paying off the limitation
listed in v0.1.0. The address family is auto-detected from the group
address; there is no `--ipv6` flag, and the IPv4 paths are byte-for-byte
unchanged (locked by regression tests and a live loopback pair).

### Added

- **IPv6 groups everywhere.** `mcast-send` and `mcast-receive` accept
  IPv6 multicast groups (`ff00::/8`), including zone-id syntax for
  link-local scopes (`ff02::42%eth1`). Sources for SSM must match the
  group's family.
- **IPv6 classification.** Dashboards and `mcast-status` classify v6
  groups by RFC 4291 flags + scope (well-known / transient /
  unicast-prefix-based / embedded-RP / SSM / solicited-node, with scope
  names and a "(not routed)" hint for interface-/link-local).
- **MLD support in `mcast-receive`.** New `--mld-version {1,2}` flag
  (MLDv1 ≈ IGMPv2, MLDv2 ≈ IGMPv3); the positional version slot is
  interpreted per family. SSM on IPv6 requires MLDv2, mirroring the
  IGMPv3 rule with the same explanation. MLD version forcing
  saves/restores `/proc/sys/net/ipv6/conf/<iface>/force_mld_version`
  exactly like the IGMP flow. Cross-family flags (`--igmp-version` on a
  v6 group and vice versa) produce educational errors.
- **IPv6 joins.** ASM via `IPV6_JOIN_GROUP` + `struct ipv6_mreq`; SSM via
  `MCAST_JOIN_SOURCE_GROUP` + a hand-packed 264-byte
  `struct group_source_req` (Python doesn't expose this option; layout is
  byte-verified against the Linux UAPI headers in the test suite).
- **Per-packet hop limit / traffic class** on the receiver via
  `IPV6_RECVHOPLIMIT` / `IPV6_RECVTCLASS` ancillary data — hop-count and
  DSCP-remark detection work identically across families.
- **`mcast-send` IPv6 plumbing:** `IPV6_MULTICAST_HOPS` / `_LOOP` /
  `_TCLASS` / `_IF` (by interface index), egress resolution via zone /
  `--interface` / route table, and a hard requirement (with guidance) for
  an interface on interface-/link-local scope groups. `--hop-limit` added
  as an alias of `--ttl`.
- **`mcast-status` IPv6 table** from `/proc/net/igmp6` with a Forced-MLD
  column. All-nodes and solicited-node groups are hidden by default
  (they're NDP plumbing, not joins); `--all` reveals them.
- **JSON summaries** gain a `"family"` field (4|6); the receiver emits
  `mld_version_requested` for v6 and keeps `igmp_version_requested` for
  v4. The `"ttl"` key is retained for both families (it carries the hop
  limit under IPv6).

### Unchanged on purpose

- **Wire format.** The 32-byte header and `PROTOCOL_VERSION = 1` are
  untouched; `orig_ttl` carries the IPv6 hop limit. v0.1.0 and v0.2.0
  tools interoperate on IPv4.
- **The operational MLD version is not displayed** anywhere —
  `/proc/net/igmp6` has no version column (unlike `/proc/net/igmp`'s
  `V3`), so the dashboard and status table honestly show only the
  requested/forced state.

### Limitations (still deliberately out of scope)

- PCAP integration on the receiver side.
- Bidirectional / round-trip-time mode.

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
