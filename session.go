//go:build unix

package ping

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	maxConsecutiveSendErrors = 3
	defaultTimeoutBufSize    = 64
	recvBufSize              = 1500 // standard Ethernet MTU
)

// runSession holds all mutable state for a single Run execution.
//
// All fields are accessed only by the main goroutine except recvWg,
// which coordinates with the background recvLoop.
type runSession struct {
	p *Pinger // shared state: conn, stats, opts, id, addr, done

	pending               map[uint16]time.Time
	nextSeq               uint16
	sentCount             int
	consecutiveSendErrors int

	recvCh        chan *EchoReply
	timeoutCh     chan uint16
	timeoutTimer  *time.Timer
	timeoutSignal chan struct{} // buffered(1); timer callback defers to main goroutine
	recvWg        sync.WaitGroup
	ticker        *time.Ticker
	dst           net.Addr
}

func (s *runSession) init() {
	s.recvCh = make(chan *EchoReply, 1)

	timeoutBuf := defaultTimeoutBufSize
	if s.p.opts.count > 0 && s.p.opts.count > timeoutBuf {
		timeoutBuf = s.p.opts.count
	}
	s.timeoutCh = make(chan uint16, timeoutBuf)
	s.timeoutSignal = make(chan struct{}, 1)

	s.pending = make(map[uint16]time.Time)

	if s.p.opts.privileged {
		s.dst = &net.IPAddr{IP: s.p.addr.IP, Zone: s.p.addr.Zone}
	} else {
		s.dst = &net.UDPAddr{IP: s.p.addr.IP, Zone: s.p.addr.Zone}
	}

	s.ticker = time.NewTicker(s.p.opts.interval)
}

func (s *runSession) mainLoop(ctx context.Context) {
	s.sendOne()

	for {
		if s.consecutiveSendErrors >= maxConsecutiveSendErrors ||
			s.countReached() && len(s.pending) == 0 {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-s.ticker.C:
			s.sendOne()
		case <-s.timeoutSignal:
			s.expireTimeouts()
		case seq := <-s.timeoutCh:
			s.handleTimeout(seq)
		case reply := <-s.recvCh:
			s.handleReply(reply)
		}
	}
}

// shutdown stops timers, signals the background goroutines to exit,
// closes the connection, and waits for cleanup to complete.
//
// Order matters: stop timers first (prevent new callbacks), then signal
// done, then close the connection (unblocks recvLoop's ReadFrom).
func (s *runSession) shutdown() {
	s.ticker.Stop()
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
	}

	select {
	case <-s.p.done:
	default:
		close(s.p.done)
	}

	_ = s.p.conn.Close()
	s.recvWg.Wait()
	clear(s.pending)
}

func (s *runSession) countReached() bool {
	return s.p.opts.count > 0 && s.sentCount >= s.p.opts.count
}

func (s *runSession) sendOne() {
	if s.countReached() {
		s.ticker.Stop()
		return
	}

	// Seq wraparound guard: if the slot is still pending at 65536 packets,
	// skip it rather than corrupting the pending map.
	if _, exists := s.pending[s.nextSeq]; exists {
		s.p.opts.logger.Warn("seq still pending (wraparound), skipping send",
			slog.Int("seq", int(s.nextSeq)))
		s.nextSeq++
		return
	}

	seq := s.nextSeq
	s.nextSeq++

	req := &EchoRequest{
		ID:   s.p.id,
		Seq:  seq,
		Size: s.p.opts.size,
	}

	err := sendEchoRequest(s.p.conn, s.dst, req)
	if err != nil {
		s.p.mu.Lock()
		s.p.stats.TxError++
		s.p.mu.Unlock()
		s.consecutiveSendErrors++

		if s.p.opts.onSendError != nil {
			s.p.opts.onSendError(req, err)
		}
		return
	}

	s.consecutiveSendErrors = 0
	s.sentCount++

	s.p.mu.Lock()
	s.p.stats.Sent++
	s.p.mu.Unlock()

	deadline := time.Now().Add(s.p.opts.timeout)
	s.pending[seq] = deadline
	s.scheduleTimeout()

	if s.p.opts.onSend != nil {
		s.p.opts.onSend(req)
	}
}

func (s *runSession) handleReply(reply *EchoReply) {
	if _, ok := s.pending[reply.Seq]; !ok {
		s.p.mu.Lock()
		s.p.stats.LateDrop++
		s.p.mu.Unlock()
		return
	}

	delete(s.pending, reply.Seq)
	s.scheduleTimeout()

	s.p.mu.Lock()
	s.p.stats.onReply(reply.RTT)
	s.p.mu.Unlock()

	if s.p.opts.onRecv != nil {
		s.p.opts.onRecv(reply)
	}
}

// recvLoop reads and parses replies in a background goroutine.
//
// Transient errors (malformed packets, validation failures) are logged
// and skipped. On shutdown, the connection is closed first to unblock
// ReadFrom --- the resulting error is silently ignored when done is closed.
func (s *runSession) recvLoop() {
	buf := make([]byte, recvBufSize)

	for {
		reply, err := recvEchoReply(s.p.conn, s.p.id, s.p.addr, s.p.opts.privileged, buf)
		if err != nil {
			select {
			case <-s.p.done:
				return
			default:
			}

			var netErr net.Error
			if errors.As(err, &netErr) && !netErr.Timeout() {
				if s.p.opts.onRecvError != nil {
					s.p.opts.onRecvError(&EchoReply{}, err)
				}
				return
			}
			s.p.opts.logger.Debug("recv error", slog.Any("err", err))
			continue
		}

		select {
		case s.recvCh <- reply:
		case <-s.p.done:
			return
		}
	}
}

// scheduleTimeout finds the earliest pending deadline and arms a timer.
//
// The timer callback runs in its own goroutine and must not touch
// s.pending directly. Instead it sends on timeoutSignal, which the
// main goroutine picks up to run expireTimeouts safely.
func (s *runSession) scheduleTimeout() {
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
	}

	var earliest time.Time
	for _, d := range s.pending {
		if earliest.IsZero() || d.Before(earliest) {
			earliest = d
		}
	}
	if earliest.IsZero() {
		s.timeoutTimer = nil
		return
	}

	d := max(time.Until(earliest), 0)
	s.timeoutTimer = time.AfterFunc(d, func() {
		select {
		case <-s.p.done:
			return
		case s.timeoutSignal <- struct{}{}:
		default:
		}
	})
}

func (s *runSession) expireTimeouts() {
	now := time.Now()
	for seq, deadline := range s.pending {
		if !deadline.After(now) {
			select {
			case <-s.p.done:
				return
			case s.timeoutCh <- seq:
			default:
				s.p.opts.logger.Warn("timeout channel full", slog.Int("seq", int(seq)))
			}
		}
	}
	s.scheduleTimeout()
}

func (s *runSession) handleTimeout(seq uint16) {
	if _, ok := s.pending[seq]; !ok {
		// Reply may have arrived between timeout firing and this handler.
		return
	}
	delete(s.pending, seq)
	s.scheduleTimeout()

	s.p.mu.Lock()
	s.p.stats.Timeout++
	s.p.mu.Unlock()

	if s.p.opts.onRecvError != nil {
		s.p.opts.onRecvError(&EchoReply{Seq: seq}, ErrTimeout)
	}
}
