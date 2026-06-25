//go:build unix

package ping

import (
	"io"
	"log/slog"
	"time"
)

type options struct {
	count       int
	size        int
	interval    time.Duration
	timeout     time.Duration
	ttl         int
	privileged  bool
	broadcast   bool
	onSend      func(*EchoRequest)
	onSendError func(*EchoRequest, error)
	onRecv      func(*EchoReply)
	onRecvError func(*EchoReply, error)
	logger      *slog.Logger
}

// Option is a functional option for configuring a Pinger.
type Option func(*options)

func defaultOptions() options {
	return options{
		count:      0,
		size:       56,
		interval:   time.Second,
		timeout:    5 * time.Second,
		ttl:        64,
		privileged: false,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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

// WithSize sets the ICMP payload size in bytes.
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

// WithTimeout sets the per-sequence reply timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) {
		if timeout > 0 {
			o.timeout = timeout
		}
	}
}

// WithTTL sets the IP Time-To-Live (1–255).
func WithTTL(ttl int) Option {
	return func(o *options) {
		if ttl > 0 && ttl <= 255 {
			o.ttl = ttl
		}
	}
}

// WithPrivileged enables raw socket mode (requires root / CAP_NET_RAW).
func WithPrivileged(v bool) Option {
	return func(o *options) {
		o.privileged = v
	}
}

// WithBroadcast allows sending ICMP Echo Requests to broadcast addresses.
func WithBroadcast(v bool) Option {
	return func(o *options) {
		o.broadcast = v
	}
}

// WithOnSend registers a callback invoked after each successful send.
func WithOnSend(fn func(*EchoRequest)) Option {
	return func(o *options) {
		o.onSend = fn
	}
}

// WithOnSendError registers a callback invoked on send failure.
func WithOnSendError(fn func(*EchoRequest, error)) Option {
	return func(o *options) {
		o.onSendError = fn
	}
}

// WithOnRecv registers a callback invoked on successful reply.
func WithOnRecv(fn func(*EchoReply)) Option {
	return func(o *options) {
		o.onRecv = fn
	}
}

// WithOnRecvError registers a callback invoked on receive error / timeout.
func WithOnRecvError(fn func(*EchoReply, error)) Option {
	return func(o *options) {
		o.onRecvError = fn
	}
}

// WithLogger injects a custom *slog.Logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}
