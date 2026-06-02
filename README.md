# ft_traceroute

A C reimplementation of `traceroute` for IPv4, built as part of the 42 UNIX projects.

## How it works

Each probe is an ICMP Echo Request sent with a low TTL. Every router that drops the packet because TTL reached zero replies with an ICMP Time Exceeded message, which reveals its IP and lets us measure the round-trip time. The TTL increments from 1 to 30 until the destination replies with an ICMP Echo Reply.

Three probes are sent per hop so packet loss and jitter are visible.

Background reading:
- [WTF is Traceroute?](https://notes.thamle.live/Networking/Traceroute)
- [WTF is ICMP?](https://notes.thamle.live/Networking/ICMP)
- [WTF is TTL?](https://notes.thamle.live/Networking/TTL)
- [WTF is a Raw Socket?](https://notes.thamle.live/Networking/Raw-Sockets)

## Usage

```
sudo ./ft_traceroute [options] <host> [packetlen]
sudo ./ft_traceroute --help
```

`host` is an IPv4 address or a hostname, resolved once at startup for the header line. By default each hop is reverse-resolved to a hostname, like `traceroute`; pass `-n` to print IP addresses only. An optional `packetlen` operand sets the probe size, same as `-l`.

Root (or `CAP_NET_RAW`) is required to open a raw ICMP socket.

### Options

```
-f <ttl>    first hop (default 1)
-m <ttl>    max hops (default 30)
-q <n>      probes per hop (default 3)
-w <sec>    per-probe timeout, may be fractional (default 5)
-N <n>      probes in flight (default 16)
-n          do not reverse-resolve hop addresses
-t <tos>    IP type-of-service byte
-p <seq>    base ICMP sequence number
-l <len>    total probe packet length in bytes (default 48)
-s <addr>   source address
-i <iface>  bind to a network interface
```

## Build

```
make        # build
make clean  # remove objects
make fclean # remove objects and binary
make re     # full rebuild
```

Requires a C compiler and standard POSIX headers. Tested on Linux.

## Tests

`run_tests.sh` runs the full suite: help, argument errors, and the network behavior of every flag. Run as root for the network tests; without root only the help and argument-error tests run.

```
sudo ./run_tests.sh
```

## Implementation notes

- Uses `select` with a per-probe timeout (no `poll`, `ppoll`, or `fcntl`).
- ICMP Echo Requests are identified by `getpid() & 0xFFFF` as the ICMP ID so concurrent runs on the same host do not interfere.
- Time Exceeded responses are validated by checking the embedded original IP and ICMP headers, not just the source address.
- On QEMU/SLiRP without host raw socket access, intermediate hops may appear as `*` because SLiRP rewrites ICMP IDs when forwarding through ping sockets. The destination hop is unaffected.

