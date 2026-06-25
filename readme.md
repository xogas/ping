# ping

A Go ICMP ping library and CLI tool with support for both privileged (raw socket) and unprivileged (UDP) modes.

## Features

- **Dual mode** --- raw ICMP sockets (root) or UDP (unprivileged)
- **IPv4 and IPv6** --- resolved automatically from the target address
- **Online statistics** --- Welford's algorithm for mean and standard deviation
- **Context-aware** --- cancel or set deadlines via `context.Context`
- **Callbacks** --- hook into send, receive, and error events
- **Zero dependencies beyond `golang.org/x/net`**

## Installation

### CLI

```bash
go install github.com/xogas/ping/cmd/ping@latest
```

### Library

```bash
go get github.com/xogas/ping
```

## CLI Usage

```bash
# Ping a host indefinitely (Ctrl+C to stop)
ping 8.8.8.8

# Send a fixed number of packets
ping -c 5 1.1.1.1

# Custom interval and payload size
ping -i 200ms -s 128 example.com

# Use a raw socket (requires root / CAP_NET_RAW)
sudo ping --privileged 8.8.8.8

# Ping an IPv6 address
ping ::1
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "time"

    "github.com/xogas/ping"
)

func main() {
    p, err := ping.New("8.8.8.8",
        ping.WithCount(4),
        ping.WithInterval(500*time.Millisecond),
        ping.WithSize(64),
        ping.WithOnRecv(func(reply *ping.EchoReply) {
            fmt.Printf("%d bytes from %s: seq=%d ttl=%d time=%.1f ms\n",
                reply.Size, reply.Addr, reply.Seq, reply.TTL,
                float64(reply.RTT)/float64(time.Millisecond))
        }),
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
        os.Exit(1)
    }

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
    defer cancel()

    stats, err := p.Run(ctx)
    if err != nil && err != context.Canceled {
        fmt.Fprintf(os.Stderr, "error: %v\n", err)
    }

    fmt.Printf("%d sent, %d received, %.1f%% loss\n",
        stats.Sent, stats.Received, stats.Loss*100)
    fmt.Printf("rtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
        durMS(stats.MinRTT), durMS(stats.AvgRTT),
        durMS(stats.MaxRTT), durMS(stats.StdDevRTT))
}

func durMS(d time.Duration) float64 {
    return float64(d) / float64(time.Millisecond)
}
```

### Options

| Option | Description |
| --- | --- |
| `WithCount(n)` | Number of requests (`0` = infinite) |
| `WithSize(n)` | ICMP payload size in bytes |
| `WithInterval(d)` | Interval between sends |
| `WithTimeout(d)` | Per-sequence reply timeout |
| `WithTTL(n)` | IP TTL (1–255) |
| `WithPrivileged(v)` | Enable raw socket mode |
| `WithBroadcast(v)` | Allow broadcast addresses |
| `WithOnSend(fn)` | Callback invoked after each successful send |
| `WithOnSendError(fn)` | Callback invoked on send failure |
| `WithOnRecv(fn)` | Callback invoked on successful reply |
| `WithOnRecvError(fn)` | Callback invoked on receive error / timeout |
| `WithLogger(l)` | Inject a custom `*slog.Logger` |

## Privileged vs Unprivileged

By default, the library uses **unprivileged mode** (UDP), which works without special permissions on most systems. ICMP Echo Requests are sent via UDP datagrams --- the kernel handles the ICMP encapsulation.

**Privileged mode** uses raw ICMP sockets (`ip4:icmp` / `ip6:ipv6-icmp`), which requires `root` or `CAP_NET_RAW`:

```bash
# Grant the capability to the binary (Linux)
sudo setcap cap_net_raw=+ep ./bin/ping
```

In privileged mode, ICMP Identifier validation is enforced since the kernel does not rewrite it.

## License

The MIT License (MIT) - see [license](./license) for more details.
