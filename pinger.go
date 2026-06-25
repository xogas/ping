//go:build unix

package ping

import (
	"context"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
)

var globalID atomic.Int32

func init() {
	// Seed with a random offset --- ICMP ID doesn't need cryptographic randomness.
	globalID.Store(int32(rand.IntN(1 << 16))) //nolint:gosec
}

func generateID() int {
	return int(globalID.Add(1)) & 0xFFFF
}

// pingerState represents the lifecycle state of a Pinger.
//
// Transitions: stateNew -> stateRunning -> stateStopped.
// Each Pinger may only be used once.
type pingerState int32

const (
	stateNew pingerState = iota
	stateRunning
	stateStopped
)

// Pinger is the core entry point of the ping library.
//
// Concurrency:
//   - Immutable after construction: host, addr, id, ipv4, opts
//   - Protected by mu: stats, conn, done
//
// Per-run mutable state lives in runSession.
type Pinger struct {
	host string
	addr *net.IPAddr
	id   int
	ipv4 bool
	opts options

	state atomic.Int32
	mu    sync.Mutex
	stats *Statistics
	conn  *packetConn
	done  chan struct{}
}

// New constructs a Pinger from a hostname or IP address.
func New(host string, opts ...Option) (*Pinger, error) {
	return NewContext(context.Background(), host, opts...)
}

// NewContext is like New but uses the provided context for DNS resolution.
func NewContext(ctx context.Context, host string, opts ...Option) (*Pinger, error) {
	if host == "" {
		return nil, ErrInvalidAddr
	}

	addr, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	return &Pinger{
		host: host,
		addr: addr,
		id:   generateID(),
		ipv4: addr.IP.To4() != nil,
		opts: o,
	}, nil
}

// Run executes the ping session. It transitions the Pinger through
// New -> Running -> Stopped.
//
// A Pinger may only be used once --- subsequent calls return ErrInvalidState.
// On error, partially collected statistics are returned when construction
// succeeded; only connection failures return nil statistics.
func (p *Pinger) Run(ctx context.Context) (*Statistics, error) {
	if !p.state.CompareAndSwap(int32(stateNew), int32(stateRunning)) {
		return nil, ErrInvalidState
	}
	defer p.state.Store(int32(stateStopped))

	done := make(chan struct{})
	p.mu.Lock()
	p.done = done
	p.mu.Unlock()

	if err := p.connect(); err != nil {
		return nil, err
	}

	s := &runSession{p: p}
	s.init()

	s.recvWg.Go(func() {
		s.recvLoop()
	})

	s.mainLoop(ctx)
	s.shutdown()

	p.mu.Lock()
	p.stats.finalize()
	p.mu.Unlock()

	if s.consecutiveSendErrors >= maxConsecutiveSendErrors {
		return p.Statistics(), ErrSendFailed
	}
	if ctx.Err() != nil {
		return p.Statistics(), ctx.Err()
	}
	return p.Statistics(), nil
}

func (p *Pinger) connect() error {
	conn, err := newPacketConn(p.ipv4, &p.opts)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.stats = &Statistics{Addr: p.addr.String()}
	p.conn = conn
	p.mu.Unlock()

	return nil
}

// Stop signals the running ping session to exit. Idempotent.
func (p *Pinger) Stop() {
	p.state.CompareAndSwap(int32(stateRunning), int32(stateStopped))
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done != nil {
		select {
		case <-p.done:
		default:
			close(p.done)
		}
	}
}

// Host returns the original hostname or IP address passed to New.
func (p *Pinger) Host() string {
	return p.host
}

// Addr returns the resolved IP address of the target.
func (p *Pinger) Addr() string {
	return p.addr.String()
}

// Statistics returns a real-time snapshot of the current statistics.
// Safe to call concurrently with Run.
//
// The snapshot is not finalized --- AvgRTT, StdDevRTT, and Loss are
// only computed when Run returns. Use Run's return value for final stats.
func (p *Pinger) Statistics() *Statistics {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stats == nil {
		return nil
	}
	c := *p.stats
	return &c
}
