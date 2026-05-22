# mcast-tools

Friendly multicast send/receive tools for lab environments. Hides the
complexity of `iperf` / raw socket plumbing behind three simple commands,
and adds capabilities iperf can't provide — source-specific (SSM) joins,
IGMP version control, hop-count and DSCP-remark visibility via embedded
metadata, and live dashboards that update in real time.

## Why not just iperf?

iperf is great, but for a teaching lab a few limitations matter:

- **No SSM joins.** `iperf -s -B <group>` only does any-source `(*,G)` joins.
  No flag fixes this — it's a socket-level capability iperf doesn't expose.
- **No IGMP version control.** That's a kernel sysctl, not an iperf knob.
- **No visibility into TTL or DSCP.** iperf doesn't tell you which interface
  the join went out on, what IGMP version was actually sent, what TTL or
  DSCP arrived, or how many hops away the sender is.
- **Output is built for log scraping, not live UX.**

`mcast-tools` keeps iperf's "two commands, easy to remember" feel while
adding the things you actually want in a lab.

## Install

```bash
pip install mcast-tools
```

Or from source:

```bash
git clone https://github.com/mitchv85/mcast-tools.git
cd mcast-tools
pip install .
```

Provides three commands: `mcast-send`, `mcast-receive`, `mcast-status`.

> **Root is recommended** for `mcast-receive` so it can force the IGMP version
> via `/proc/sys/net/ipv4/conf/<iface>/force_igmp_version`. It will still
> run without root, but the kernel will use whatever IGMP version it's
> currently configured for.

## Quick start

```bash
# Sender — defaults to 10 minutes, TTL 100, 25pps, DSCP=BE
mcast-send 239.0.10.101

# Receiver — defaults to ASM (*,G) join, IGMPv3
mcast-receive 239.0.10.101

# What groups is this host joined to?
mcast-status
```

## `mcast-send`

```
mcast-send <group> [duration] [ttl]
mcast-send <group> --rate 1Mbps --dscp ef --interface eth1
```

| Option | Default | Purpose |
|---|---|---|
| `group` | (required) | IPv4 multicast group, e.g. `239.0.10.101` |
| `duration` | `600` | Seconds to send. `0` = forever |
| `ttl` | `100` | IP TTL on outgoing packets |
| `--rate` | `25pps` | `Npps`, `Nkbps`, `NMbps`, etc. |
| `--size` | `200` | Datagram size in bytes (header + payload) |
| `--dscp` | `be` | `0`-`63` or name (`ef`, `af41`, `cs5`, ...) |
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
```

| Option | Default | Purpose |
|---|---|---|
| `group` | (required) | IPv4 multicast group |
| `source` | (none) | Source IP for SSM `(S,G)` join |
| `igmp_version` | `3` | `1`, `2`, or `3`. **Must be 3 if a source is specified.** |
| `--interface` | (routing default) | Interface to join on |
| `--stall-timeout` | `3.0` | Seconds without a packet before flagging STALLED |
| `--duration` | `0` | Auto-stop after N seconds (`0` = run forever) |
| `--quiet` / `--json` | off | Suppress dashboard / emit JSON summary on exit |

The receiver continuously displays:

- **Status:** `WAITING` → `RECEIVING` → `STALLED` based on packet arrival
- **Received TTL** with hop-count interpretation (`recv 96, sender set 100 — 4 hops away`)
- **Received DSCP** with remark detection (`BE, sender set EF — REMARKED`)
- **Loss / Duplicates / Reordered** counters
- **Sender restart detection** (new `sender_id` → restart counter increments)
- **Gap log** — recent stall events with duration

### Why IGMPv3 is mandatory for SSM

Only IGMPv3 Membership Reports carry the per-source state needed to
communicate `(S,G)` filtering up to the querier. v1/v2 reports only express
`(*,G)`. `mcast-receive` enforces this with a clear error message rather
than silently doing the wrong thing.

## `mcast-status`

```
mcast-status              # current memberships, excluding kernel defaults
mcast-status --all        # include 224.0.0.1 etc.
mcast-status -i eth0      # one interface only
```

Reads `/proc/net/igmp` and pretty-prints which interfaces are joined to
which groups, the operational IGMP version, and the current
`force_igmp_version` value if any.

## End-to-end example

In one terminal:

```bash
mcast-receive 239.0.10.101
```

In another:

```bash
mcast-send 239.0.10.101 --rate 50pps --ttl 64 --dscp ef
```

The receiver will show 50 pps, EF DSCP preserved, and a hop count derived
from the difference between the sender-stamped original TTL (64) and the
TTL observed on arrival. If anything in the path remarks DSCP or
decrements TTL more than expected, you'll see it immediately.

## Behind-the-scenes details (worth knowing for a lab)

- **Destination UDP port** is `19779` (`0x4D43` = `"MC"`). Choose this if you
  need to filter in tcpdump: `tcpdump 'udp port 19779 and host 239.0.10.101'`.
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

## License

MIT. See `LICENSE`.
