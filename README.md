# ft_traceroute

A C reimplementation of `traceroute` for IPv4, built as part of the 42 UNIX projects.

## How it works

Probes are UDP datagrams sent with increasing TTL values, starting at 1. Each router that discards a packet because the TTL hit zero replies with an ICMP Time Exceeded message, revealing its IP and round-trip time. When the destination receives the probe it replies with ICMP Port Unreachable, marking the end of the trace. Pass `-I` to use ICMP Echo instead of UDP, same as `traceroute -I`.

Multiple probes are sent per hop (default 3) so packet loss and jitter are visible. Up to 16 probes fly in parallel by default, so the trace does not wait for each hop to finish before probing the next.

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

`host` is an IPv4 address or hostname. By default each hop address is reverse-resolved to a hostname; pass `-n` to skip DNS. Root (or `CAP_NET_RAW`) is required to open a raw ICMP socket.

### Options

```
-f, --first=N        Start from hop N (default 1)
-I, --icmp           Use ICMP Echo instead of UDP
-m, --max-hops=N     Max hops (default 30)
-N, --sim-queries=N  Simultaneous probes in flight (default 16)
-n                   No DNS resolution
-p, --port=N         Base destination port (default 33434, UDP mode only)
-q, --queries=N      Probes per hop (default 3)
-l N                 Packet length in bytes (default 60)
-h, --help           Show this help
```

## Build

```
make        # build
make clean  # remove objects
make fclean # remove objects and binary
make re     # full rebuild
```

Requires GCC and standard POSIX headers. Tested on Linux.

## Docker

Requires a standard (root) Docker daemon. Rootless Docker does not support raw sockets because the network backend runs in userspace and cannot grant real `CAP_NET_RAW`.

```
make docker       # build the image
make docker-shell # interactive shell for testing
```

Inside the shell, both `./ft_traceroute` and `traceroute` are available for comparison.

## Implementation notes

- Uses `select` with per-probe deadlines, no `poll`, `ppoll`, or `fcntl`.
- In UDP mode, each probe gets a unique destination port derived from the base port, hop index, and probe index. ICMP Time Exceeded replies carry the original UDP header so the right probe can be matched without extra socket state.
- In ICMP mode, the process PID is used as the ICMP ID so concurrent runs on the same host do not interfere.
- ICMP error responses are validated by parsing the embedded original IP and transport headers, not just the source address.
- Port arithmetic uses explicit `uint16_t` casts so the sequence wraps correctly past 65535.
- `checksum` avoids strict-aliasing UB by using `ft_memcpy` instead of pointer punning.
