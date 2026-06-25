//go:build unix

// Ping is a CLI tool that sends ICMP Echo Requests to a target host and
// reports round-trip time statistics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xogas/ping"
)

func main() {
	host, size, opts := parseFlags()

	pinger, err := ping.New(host, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("PING %s (%s): %d bytes of data.\n", pinger.Host(), pinger.Addr(), size)

	stats, runErr := runWithSignals(pinger)
	handleResult(stats, runErr)
}

func parseFlags() (host string, size int, opts []ping.Option) {
	count := flag.Int("c", 0, "number of echo requests to send (0 = infinite)")
	sizePtr := flag.Int("s", 56, "ICMP payload size in bytes")
	interval := flag.Duration("i", time.Second, "interval between sends")
	ttl := flag.Int("t", 64, "IP TTL")
	timeout := flag.Duration("W", 5*time.Second, "per-seq reply timeout")
	privileged := flag.Bool("privileged", false, "use raw socket (requires root)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: ping [options] <host>\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	opts = []ping.Option{
		ping.WithCount(*count),
		ping.WithSize(*sizePtr),
		ping.WithInterval(*interval),
		ping.WithTTL(*ttl),
		ping.WithTimeout(*timeout),
		ping.WithPrivileged(*privileged),
		ping.WithOnRecv(func(reply *ping.EchoReply) {
			printReply(reply)
		}),
		ping.WithOnRecvError(func(reply *ping.EchoReply, err error) {
			fmt.Printf("Request timeout for icmp_seq %d: %v\n", reply.Seq, err)
		}),
	}

	return args[0], *sizePtr, opts
}

func runWithSignals(pinger *ping.Pinger) (*ping.Statistics, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println()
		cancel()
	}()

	return pinger.Run(ctx)
}

func handleResult(stats *ping.Statistics, runErr error) {
	if stats != nil {
		printStatistics(stats)
	}

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", runErr)
		os.Exit(1)
	}
}

func durMS(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func printReply(r *ping.EchoReply) {
	fmt.Printf("%d bytes from %v: icmp_seq=%d ttl=%d time=%.1f ms\n",
		r.Size, r.Addr, r.Seq, r.TTL, durMS(r.RTT))
}

func printStatistics(s *ping.Statistics) {
	fmt.Printf("--- %s ping statistics ---\n", s.Addr)
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		s.Sent, s.Received, s.Loss*100)
	if s.Received > 0 {
		fmt.Printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
			durMS(s.MinRTT), durMS(s.AvgRTT), durMS(s.MaxRTT), durMS(s.StdDevRTT))
	}
}
