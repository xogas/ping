//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xogas/ping"
)

func main() {
	// Parse command-line flags.
	count := flag.Int("c", 0, "number of echo requests to send (0 = infinite)")
	size := flag.Int("s", 56, "ICMP payload size in bytes")
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
	host := args[0]

	// Build options.
	opts := []ping.Option{
		ping.WithCount(*count),
		ping.WithSize(*size),
		ping.WithInterval(*interval),
		ping.WithTTL(*ttl),
		ping.WithTimeout(*timeout),
		ping.WithPrivileged(*privileged),
		ping.WithOnSend(func(req *ping.EchoRequest) {
			fmt.Printf("PING %s: seq=%d size=%d\n", host, req.Seq, req.Size)
		}),
		ping.WithOnRecv(func(reply *ping.EchoReply) {
			printReply(reply)
		}),
		ping.WithOnRecvError(func(reply *ping.EchoReply, err error) {
			fmt.Printf("Request timeout for icmp_seq %d: %v\n", reply.Seq, err)
		}),
	}

	// Create Pinger.
	pinger, err := ping.New(host, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Set up context with signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for SIGINT/SIGTERM to gracefully stop.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println()
		pinger.Stop()
		cancel()
	}()

	fmt.Printf("PING %s: %d data bytes\n", host, *size)

	// Run the pinger.
	stats, runErr := pinger.Run(ctx)

	// Print statistics.
	if stats != nil {
		fmt.Println()
		printStatistics(stats)
	}

	if runErr != nil && runErr != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error: %v\n", runErr)
		os.Exit(1)
	}
}

// printReply formats and prints a single reply line.
func printReply(r *ping.EchoReply) {
	fmt.Printf("%d bytes from %v: icmp_seq=%d ttl=%d time=%.3f ms\n",
		r.Size, r.Addr, r.Seq, r.TTL,
		float64(r.RTT.Microseconds())/1000.0)
}

// printStatistics formats and prints the statistics summary.
func printStatistics(s *ping.Statistics) {
	fmt.Printf("--- %s ping statistics ---\n", s.Addr)
	fmt.Printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
		s.Sent, s.Received, s.Loss*100)
	if s.Received > 0 {
		fmt.Printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
			float64(s.MinRTT.Microseconds())/1000.0,
			float64(s.AvgRTT.Microseconds())/1000.0,
			float64(s.MaxRTT.Microseconds())/1000.0,
			float64(s.StdDevRTT.Microseconds())/1000.0)
	}
}
