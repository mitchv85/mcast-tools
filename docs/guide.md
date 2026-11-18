# mcast-tools guide

The full reference for `mcast-send`, `mcast-receive` and `mcast-status`.
For the overview, see the [README](../README.md).

- [Why not just iperf?](#why-not-just-iperf)
- [Install](#install)
- [`mcast-send`](#mcast-send)
- [`mcast-receive`](#mcast-receive)
- [`mcast-status`](#mcast-status)
- [End-to-end example](#end-to-end-example)
- [IPv6 specifics](#ipv6-specifics)
- [Windows](#windows)
- [Behind-the-scenes details](#behind-the-scenes-details-worth-knowing-for-a-lab)

## Why not just iperf?

iperf is great, but for a teaching lab a few limitations matter:

- **SSM without guard rails.** iperf 2 can join `(S,G)` with
  `-B <group> -H <source>` (`--ssm-host`), but nothing checks or explains
  the IGMPv3/MLDv2 rule an SSM join depends on.
- **No IGMP version control.** That's a kernel sysctl, not an iperf knob.
- **No visibility into TTL or DSCP.** iperf doesn't tell you which interface
  the join went out on, what IGMP version was actually sent, what TTL or
  DSCP arrived, or how many hops away the sender is.
- **Output is built for log scraping, not live UX.**

`mcast-tools` keeps iperf's "two commands, easy to remember" feel while
adding the things you actually want in a lab.

## Install

```bash
pipx install mcast-tools    # or: pip install mcast-tools
```

Or from source:

```bash
git clone https://github.com/mitchv85/mcast-tools.git
cd mcast-tools
pip install .
```

Provides three commands: `mcast-send`, `mcast-receive`, `mcast-status`.

> **On Linux, root is recommended** for `mcast-receive` so it can force the
> IGMP/MLD version via `/proc/sys/net/ipv4/conf/<iface>/force_igmp_version`
> or `/proc/sys/net/ipv6/conf/<iface>/force_mld_version`. It will still
> run without root, but the kernel will use whatever version it's
> currently configured for. With pipx or a virtualenv, `sudo` won't find
> the command on its PATH, so run `sudo "$(command -v mcast-receive)" <group>`.

## `mcast-send`

```
mcast-send <group> [duration] [ttl]
mcast-send <group> --rate 1Mbps --dscp ef --interface eth1
```

| Option | Default | Purpose |
|---|---|---|
| `group` | (required) | IPv4 or IPv6 multicast group, e.g. `239.0.10.101` or `ff3e::8000:1` |
| `duration` / `--duration` | `600` | Seconds to send. `0` = forever |
| `ttl` | `100` | IPv4 TTL / IPv6 hop limit (`--hop-limit` is an alias of `--ttl`) |
| `--rate` | `25pps` | `Npps`, `Nkbps`, `NMbps`, etc. |
| `--size` | `200` | Datagram size in bytes (header + payload) |
| `--dscp` | `be` | `0`-`63` or name (`ef`, `af41`, `cs5`, ...) |
| `--source` | (kernel-selected) | Bind the outgoing **source address**. Pin it for SSM demos — see [IPv6 specifics](#ipv6-specifics). |
| `--interface` | (routing default) | Egress interface override |
| `--no-loopback` | off | Disable `IP_MULTICAST_LOOP` |
| `--quiet` / `--json` | off | Suppress dashboard / emit JSON summary on exit |

Each packet carries a 32-byte custom header with magic `MCAS`, a sequence
number, a monotonic nanosecond timestamp, a random per-invocation sender ID,
and the original TTL/DSCP the sender configured. `mcast-receive` uses these
fields to compute loss, duplicates, reordering, hop count, and DSCP remarks.

## `mcast-receive`

```
mcast-receive <group>                                  # ASM (*,G)
mcast-receive <group> <source>                         # SSM (S,G), IGMPv3
mcast-receive <group> --igmp-version 2 --interface eth1
mcast-receive ff3e::8000:1 --source 2001:db8::5 -i eth1   # IPv6 SSM, MLDv2
```

| Option | Default | Purpose |
|---|---|---|
| `group` | (required) | IPv4 or IPv6 multicast group |
| `source` | (none) | Source IP for SSM `(S,G)` join — same family as the group |
| `igmp_version` | `3` / `2` | Positional version: IGMP `1`/`2`/`3` for IPv4 groups, MLD `1`/`2` for IPv6 groups. **SSM needs IGMPv3 / MLDv2.** |
| `--mld-version` | `2` | MLD version for IPv6 groups (`--igmp-version` is IPv4-only) |
| `--interface` | (routing default) | Interface to join on |
| `--stall-timeout` | `3.0` | Seconds without a packet before flagging STALLED |
| `--duration` | `0` | Auto-stop after N seconds (`0` = run forever) |
| `--quiet` / `--json` | off | Suppress dashboard / emit JSON summary on exit |

The receiver continuously displays:

- **Status:** `WAITING` → `RECEIVING` → `STALLED` based on packet arrival
- **Received TTL** with hop-count interpretation (`recv 96  (sender set 100, 4 hops away)`)
- **Received DSCP** with remark detection (`AF41 (34)  (sender set EF (46) — REMARKED)`)
- **Loss / Duplicates / Reordered** counters
- **Sender restart detection** (new `sender_id` → restart counter increments)
- **Gap log** — recent stall events with duration

### Why IGMPv3 / MLDv2 is mandatory for SSM

Only IGMPv3 Membership Reports carry the per-source state needed to
communicate `(S,G)` filtering up to the querier. v1/v2 reports only express
`(*,G)`. The IPv6 story is identical with the names shifted: MLDv1 maps to
IGMPv2 (ASM only) and MLDv2 maps to IGMPv3 (adds the source lists). There
is no MLD analog of IGMPv1. `mcast-receive` enforces this with a clear
error message rather than silently doing the wrong thing.

## `mcast-status`

```
mcast-status              # current memberships, excluding kernel defaults
mcast-status --all        # include 224.0.0.1 etc.
mcast-status -i eth0      # one interface only
```

Linux only. Reads `/proc/net/igmp` and `/proc/net/igmp6` and pretty-prints
which interfaces are joined to which groups. The IPv4 table includes the
operational IGMP version and the `force_igmp_version` setting. The IPv6
table shows only the *forced* MLD state — the kernel doesn't expose the
operational MLD version in `/proc/net/igmp6`, so we don't invent one. By
default the v6 view hides all-nodes (`ff02::1`, `ff01::1`) and
solicited-node (`ff02::1:ffxx:xxxx`) groups — NDP plumbing, not joins —
which means a freshly-booted host shows an *empty* v6 table until
something actually joins. `--all` reveals everything.

## End-to-end example

In one terminal:

```bash
mcast-receive 239.0.10.101
```

In another:

```bash
mcast-send 239.0.10.101 --rate 50pps --ttl 64 --dscp ef
```

The receiver will show 50 pps and, on Linux, EF DSCP preserved and a hop
count derived from the difference between the sender-stamped original TTL
(64) and the TTL observed on arrival. If anything in the path remarks DSCP or
decrements TTL more than expected, you'll see it immediately.

## IPv6 specifics

- **Family auto-detection.** The group address decides everything; there is
  no `--ipv6` flag. Sources must match the group's family.
- **Pin the sender's source for SSM.** Without `--source`, the kernel picks
  the source via RFC 6724 source-address selection — and when an interface
  carries multiple same-prefix globals (say, a static address plus a SLAAC
  EUI-64 from a router's RA), *every selection rule ties* and the pick is
  unspecified. It can differ across runs. An SSM receiver filtering on
  "the other one" then silently receives nothing while both ends work
  perfectly. `mcast-send G --source S` binds the socket, which removes
  selection from the picture; pair it with the matching
  `mcast-receive G --source S` so the same `S` flows through the whole
  (S,G) demo. (The bind sets the source, not the egress — add
  `--interface` for fully deterministic egress. The same flag works on
  IPv4, where it matters once a host carries secondaries or VIPs.)
- **Scopes and zones.** Interface-local (`ff01::`) and link-local (`ff02::`)
  scope groups never appear usefully in the routing table, so the kernel
  must be told which interface — give a zone (`ff02::42%eth1`) or
  `--interface`. Conflicting zone + `--interface` is an explicit error.
  Interface-local groups never leave the host, so use link-local `ff02::`
  to reach other machines on the link. Routable scopes (site `ff05::`,
  global `ff0e::`, the SSM range `ff3x::`) resolve via the route table
  like IPv4 does.
- **Hop limit & traffic class.** `--ttl`/`--hop-limit` sets
  `IPV6_MULTICAST_HOPS`; `--dscp` sets the traffic class, whose byte layout
  matches the IPv4 TOS byte — so remark detection works identically across
  families. The wire header is unchanged from v0.1: `orig_ttl` simply
  carries the hop limit on IPv6.
- **Joins.** ASM uses `IPV6_JOIN_GROUP` (`struct ipv6_mreq`). SSM uses the
  protocol-independent `MCAST_JOIN_SOURCE_GROUP` with a hand-packed
  `struct group_source_req` — there is no `IPV6_ADD_SOURCE_MEMBERSHIP`.
- **MLD forcing** mirrors IGMP forcing via
  `/proc/sys/net/ipv6/conf/<iface>/force_mld_version` (saved and restored
  on exit). `0` means auto, which on modern kernels is MLDv2.
- **Group hygiene** on the receive socket uses `IPV6_MULTICAST_ALL=0`
  (kernel 4.20+; silently best-effort on older kernels).

## Windows

`mcast-send` and `mcast-receive` run natively on Windows. Version 0.2.3 was
verified on Windows 11 receiving IPv4 and IPv6, ASM and SSM, from Linux
senders, and sending and receiving IPv4 on one Windows host. Sending IPv6,
or sending to a Linux receiver, from Windows hasn't been verified yet. A
few things work differently:

- **Firewall.** Windows Defender Firewall drops inbound multicast to Python
  unless a rule allows it, and the receiver just sits at `WAITING`. From an
  elevated PowerShell:

  ```powershell
  New-NetFirewallRule -DisplayName "mcast-receive UDP 19779" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 19779 -Profile Private
  ```

  If `Get-NetConnectionProfile` shows the network as `Public` or
  `DomainAuthenticated`, add `Public` or `Domain` to `-Profile`, for
  example `-Profile Private,Domain`.
- **Received TTL and DSCP** can't be read on Windows (Python has no
  `recvmsg` there), so the dashboard shows them as `n/a on this platform`
  next to what the sender set. Loss, duplicates, reordering, stalls and
  rates work exactly as on Linux.
- **IGMP/MLD version** is a host-wide setting on Windows
  (`Set-NetIPv4Protocol -IGMPVersion`, `Set-NetIPv6Protocol -MldVersion`),
  so `mcast-receive` leaves it alone; the dashboard shows
  `OS setting (not forced on Windows)`.
- **Interfaces.** Interface names can't be looked up on Windows yet. IPv4
  joins and sends use the OS default interface, and `--interface` is
  ignored with a warning. For IPv6, a zone or `--interface` on the receiver
  takes the interface index: the `%number` that `ipconfig` shows after an
  `fe80::` address, as in `mcast-receive ff02::42%12` (a name there is an
  error). The sender can't take an index yet, so leave `--interface` off
  IPv6 sends; sending to link-local IPv6 groups from Windows isn't
  supported yet.
- **`mcast-status`** reads Linux's `/proc`. On Windows,
  `netsh interface ipv4 show joins` (or `ipv6`) lists the host's
  memberships.
- **DSCP from Windows senders.** Windows may ignore DSCP values that
  applications set unless a QoS policy allows them. If a Windows sender's
  `--dscp` arrives as `REMARKED`, that's the likely cause.
- **WSL senders.** If a Linux distro in WSL has no IPv6 address, check that
  IPv6 is enabled on the Windows adapter
  (`Get-NetAdapterBinding -ComponentID ms_tcpip6`), then restart WSL with
  `wsl --shutdown`.
- **Redirected output.** On consoles that aren't set to UTF-8, writing the
  dashboard to a file can fail on its box-drawing characters. Use
  `--quiet --json`, or set `PYTHONUTF8=1`.

## Behind-the-scenes details (worth knowing for a lab)

- **Destination UDP port** is `19779` (`0x4D43` = `"MC"`) for both families.
  Filter in tcpdump: `tcpdump 'udp port 19779 and host 239.0.10.101'` or
  `tcpdump 'udp port 19779 and ip6 host ff3e::8000:1'`.
- **Default datagram size** is 200 bytes (32-byte header + 168-byte payload).
  Configure with `--size`. Minimum is 32 bytes (header only).
- **Packet padding** is `0xA5` repeated — easy to eyeball in a capture.
- **Sender ID randomization** means restarting a sender looks like a brand-new
  sender on the receiver, which is exactly the right semantic — we don't
  want the receiver to interpret a restart as a giant burst of packet loss.
- **Per-sender sequence tracking** means a receiver listening to multiple
  senders (or one sender across restarts) doesn't conflate their sequence
  spaces.
- **Stall detection** is interval-based, not packet-rate-based — we don't
  need a control channel to know the sender's target rate.
- **Foreign packet counter** counts UDP datagrams on the group that don't
  start with the `MCAS` magic header. Useful for detecting when something
  else (real video, iperf, etc.) is sharing the group.
