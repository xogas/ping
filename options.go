//go:build linux

package ping

import "time"

// options holds the configurable parameters for a Pinger.
// Users set these via the functional Options pattern.
type options struct {
	count             int                       // Number of echo requests to send, 0 means infinite
	size              int                       // ICMP payload size in bytes
	interval          time.Duration             // Interval between sends
	timeout           time.Duration             // Per-seq reply timeout
	ttl               int                       // IP TTL
	privileged        bool                      // Use raw socket (requires root)
	callbackQueueSize int                       // Callback event queue capacity, 0 uses default (64)
	mark              int                       // SO_MARK socket mark, 0 means not set
	dontFragment      bool                      // DF bit: prohibit IP fragmentation
	broadcast         bool                      // SO_BROADCAST: allow sending to broadcast addresses
	onSend            func(*EchoRequest)        // Called after each successful send, nil to skip
	onSendError       func(*EchoRequest, error) // Called on send failure, nil to skip
	onRecv            func(*EchoReply)          // Called on successful reply, nil to skip
	onRecvError       func(*EchoReply, error)   // Called on recv error (timeout/ICMP error), nil to skip
	logger            Logger                    // Logger instance
}

// Option is a functional option for configuring a Pinger.
type Option func(*options)

// defaultOptions returns a sensible set of defaults.
func defaultOptions() options {
	return options{
		count:             0, // 0 means infinite
		size:              56,
		interval:          time.Second,
		timeout:           5 * time.Second,
		ttl:               64,
		privileged:        false,
		callbackQueueSize: 0, // 0 means use default (64)
		logger:            NoopLogger{},
	}
}

// WithCount sets the number of echo requests to send. 0 means infinite.
func WithCount(count int) Option {
	return func(o *options) {
		if count >= 0 {
			o.count = count
		}
	}
}

// WithSize sets the size of the ICMP payload in bytes.
func WithSize(size int) Option {
	return func(o *options) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithInterval sets the interval between sending each echo request.
func WithInterval(interval time.Duration) Option {
	return func(o *options) {
		if interval > 0 {
			o.interval = interval
		}
	}
}

// WithTimeout sets the per-seq timeout for waiting for an echo reply.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) {
		if timeout > 0 {
			o.timeout = timeout
		}
	}
}

// WithTTL sets the IP Time-To-Live (1-255).
func WithTTL(ttl int) Option {
	return func(o *options) {
		if ttl > 0 && ttl <= 255 {
			o.ttl = ttl
		}
	}
}

// WithPrivileged enables or disables raw socket (privileged) mode.
func WithPrivileged(v bool) Option {
	return func(o *options) {
		o.privileged = v
	}
}

// WithLogger injects a custom Logger implementation.
func WithLogger(l Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithCallbackQueueSize sets the callback event queue capacity. Default is 64.
// When the queue is full, new events are dropped and a warning is logged.
func WithCallbackQueueSize(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.callbackQueueSize = n
		}
	}
}

// WithMark sets the SO_MARK socket option for policy routing / netfilter matching.
// Requires CAP_NET_ADMIN.
func WithMark(mark int) Option {
	return func(o *options) {
		o.mark = mark
	}
}

// WithDontFragment sets the DF (Don't Fragment) bit on IP packets.
// Used for Path MTU Discovery.
func WithDontFragment(v bool) Option {
	return func(o *options) {
		o.dontFragment = v
	}
}

// WithBroadcast allows sending ICMP Echo Requests to broadcast addresses.
func WithBroadcast(v bool) Option {
	return func(o *options) {
		o.broadcast = v
	}
}

// WithOnSend registers a callback invoked after each successful send (async dispatch).
func WithOnSend(fn func(*EchoRequest)) Option {
	return func(o *options) {
		o.onSend = fn
	}
}

// WithOnSendError registers a callback invoked on send failure (async dispatch).
func WithOnSendError(fn func(*EchoRequest, error)) Option {
	return func(o *options) {
		o.onSendError = fn
	}
}

// WithOnRecv registers a callback invoked on successful reply (async dispatch).
func WithOnRecv(fn func(*EchoReply)) Option {
	return func(o *options) {
		o.onRecv = fn
	}
}

// WithOnRecvError registers a callback invoked on recv error (timeout/ICMP error, async dispatch).
func WithOnRecvError(fn func(*EchoReply, error)) Option {
	return func(o *options) {
		o.onRecvError = fn
	}
}
