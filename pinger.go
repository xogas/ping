//go:build linux

package ping

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

// globalID is the process-wide atomic counter for generating unique ICMP Identifiers.
var globalID atomic.Int32

func init() {
	// Seed with a random offset to reduce collision risk across processes.
	globalID.Store(int32(rand.Intn(1 << 16)))
}

// generateID returns a unique 16-bit ICMP Identifier using atomic increment + random seed.
func generateID() int {
	return int(globalID.Add(1)) & 0xFFFF
}

// pingerState represents the lifecycle state of a Pinger.
type pingerState int

const (
	stateNew      pingerState = iota // Initial state, Run can be called
	stateRunning                     // Run is executing, reject concurrent Run
	stateStopping                    // Stop called, cleaning up
	stateStopped                     // Terminated, not reusable
)

// Pinger is the core entry point of the ping library.
type Pinger struct {
	host     string        // Original hostname or IP
	addr     *net.IPAddr   // Resolved IP address (populated during Run)
	id       int           // ICMP Identifier (16-bit)
	ipv4     bool          // Whether the target is IPv4
	state    pingerState   // Lifecycle state
	opts     options       // Configuration
	stats    *Statistics   // Runtime statistics
	conn     packetConn    // Underlying connection
	done     chan struct{} // Shutdown signal
	mu       sync.RWMutex  // Protects state/stats/conn/done
	stopOnce sync.Once     // Ensures Stop is idempotent
}

// New constructs a Pinger: applies options, generates a 16-bit ICMP ID,
// initializes state to New, and returns a ready instance.
// Note: DNS resolution is deferred to Run(); New() does not perform network I/O.
func New(host string, opts ...Option) (*Pinger, error) {
	if host == "" {
		return nil, ErrInvalidAddr
	}

	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	return &Pinger{
		host:  host,
		id:    generateID(),
		state: stateNew,
		opts:  o,
		done:  make(chan struct{}),
	}, nil
}

// Run is the public entry point: resolves host to IP, creates packetConn,
// executes the main loop via p.run(ctx), and manages state transitions
// New -> Running -> Stopping -> Stopped.
//
// If called in Running/Stopping/Stopped state, returns ErrInvalidState.
// On exit, closes the connection, computes and returns the Statistics snapshot.
// Even on error exit, returns partially collected statistics (*Statistics non-nil);
// only when construction phase fails (DNS/connection) is *Statistics nil.
func (p *Pinger) Run(ctx context.Context) (*Statistics, error) {
	// State check: only allow transition from New to Running.
	p.mu.Lock()
	if p.state != stateNew {
		p.mu.Unlock()
		return nil, ErrInvalidState
	}
	p.state = stateRunning
	p.mu.Unlock()

	// Ensure we transition to Stopped on exit.
	defer func() {
		p.mu.Lock()
		p.state = stateStopped
		p.mu.Unlock()
	}()

	// Resolve host to IP address.
	addr, err := resolve(ctx, p.host)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.addr = addr
	p.ipv4 = isIPv4(addr.IP)
	p.mu.Unlock()

	// Initialize statistics.
	stats := newStatistics(addr.String())
	p.mu.Lock()
	p.stats = stats
	p.mu.Unlock()

	// Create packet connection.
	conn, err := newPacketConn(p.ipv4, p.id, &p.opts)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.conn = conn
	p.mu.Unlock()

	// Execute main loop.
	runErr := p.run(ctx)

	// Transition to Stopping (done in run's cleanup).
	p.mu.Lock()
	p.state = stateStopping
	statsCopy := *p.stats
	p.mu.Unlock()

	return &statsCopy, runErr
}

// Stop actively stops the Pinger: idempotently closes the done channel,
// triggering the main loop to exit.
func (p *Pinger) Stop() {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.done != nil {
			select {
			case <-p.done:
				// Already closed.
			default:
				close(p.done)
			}
		}
	})
}

// Statistics returns a real-time snapshot copy of the current statistics.
// Safe to call during Run execution.
// Note: this snapshot has not called compute(), so AvgRTT/StdDevRTT/Loss
// may not be calculated yet. Use Run()'s return value for final statistics.
func (p *Pinger) Statistics() *Statistics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.stats == nil {
		return nil
	}
	copy := *p.stats
	return &copy
}
