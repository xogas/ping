//go:build linux

package ping

import (
	"context"
	"net"
	"time"
)

// maxConsecutiveSendErrors is the threshold for consecutive send failures.
// Exceeding this causes Run to return ErrSendFailed.
const maxConsecutiveSendErrors = 3

// pendingEntry records a sent Echo Request awaiting a reply.
type pendingEntry struct {
	timer *time.Timer // per-seq timeout timer
}

// callbackEvent wraps a callback to be dispatched asynchronously.
type callbackEvent struct {
	fn func() // closure capturing the specific callback and its arguments
}

// recvResult encapsulates a result from recvLoop to the main loop.
type recvResult struct {
	reply *EchoReply
	err   error // nil: normal reply; non-nil: unrecoverable error
}

// run executes the send/receive main loop.
func (p *Pinger) run(ctx context.Context) error {
	// Determine callback queue size.
	cbQueueSize := p.opts.callbackQueueSize
	if cbQueueSize <= 0 {
		cbQueueSize = 64
	}

	// Create channels.
	done := make(chan struct{})
	p.mu.Lock()
	p.done = done
	p.mu.Unlock()

	recvCh := make(chan recvResult, 1)

	// timeoutCh buffer size: max(count, 64).
	timeoutBuf := 64
	if p.opts.count > 0 && p.opts.count > timeoutBuf {
		timeoutBuf = p.opts.count
	}
	timeoutCh := make(chan uint16, timeoutBuf)

	callbackCh := make(chan callbackEvent, cbQueueSize)

	// Pending table: seq -> pendingEntry.
	pending := make(map[uint16]*pendingEntry)

	// Sequence counter.
	var nextSeq uint16

	// Consecutive send error counter.
	consecutiveSendErrors := 0

	// Rate limiter for callback queue full warnings.
	var lastWarnTime time.Time

	// Start dispatcher goroutine for async callback dispatch.
	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		for ev := range callbackCh {
			func() {
				defer func() {
					if r := recover(); r != nil {
						p.opts.logger.Errorf("callback panic: %v", r)
					}
				}()
				ev.fn()
			}()
		}
	}()

	// Start recvLoop goroutine.
	recvLoopDone := make(chan struct{})
	go func() {
		defer close(recvLoopDone)
		p.recvLoop(recvCh)
	}()

	// Helper to enqueue a callback event (non-blocking).
	enqueueCallback := func(fn func()) {
		if fn == nil {
			return
		}
		select {
		case callbackCh <- callbackEvent{fn: fn}:
		default:
			now := time.Now()
			if now.Sub(lastWarnTime) >= time.Second {
				p.opts.logger.Warnf("callback queue full, event dropped")
				lastWarnTime = now
			}
		}
	}

	// Build destination address for sending.
	var dst net.Addr
	if p.opts.privileged {
		dst = &net.IPAddr{IP: p.addr.IP, Zone: p.addr.Zone}
	} else {
		dst = &net.UDPAddr{IP: p.addr.IP, Zone: p.addr.Zone}
	}

	isV4 := isIPv4(p.addr.IP)

	// Create ticker for sending.
	ticker := time.NewTicker(p.opts.interval)
	defer ticker.Stop()

	sentCount := 0
	tickerStopped := false

	// Send the first packet immediately.
	sendOne := func() {
		// Check if count reached.
		if p.opts.count > 0 && sentCount >= p.opts.count {
			if !tickerStopped {
				ticker.Stop()
				tickerStopped = true
			}
			return
		}

		// Check Seq wraparound: if pending[nextSeq] exists, skip this round.
		if _, exists := pending[nextSeq]; exists {
			p.opts.logger.Warnf("seq %d still pending (wraparound), skipping send", nextSeq)
			nextSeq++
			return
		}

		seq := nextSeq
		nextSeq++

		req := &EchoRequest{
			ID:   p.id,
			Seq:  seq,
			Size: p.opts.size,
		}

		p.mu.Lock()
		p.stats.onSendAttempt()
		p.mu.Unlock()

		err := sendEchoRequest(p.conn, dst, req, isV4)
		if err != nil {
			p.mu.Lock()
			p.stats.onSendError()
			p.mu.Unlock()

			consecutiveSendErrors++

			if p.opts.onSendError != nil {
				reqCopy := *req
				enqueueCallback(func() {
					p.opts.onSendError(&reqCopy, err)
				})
			}

			if consecutiveSendErrors >= maxConsecutiveSendErrors {
				return
			}
			return
		}

		// Send succeeded.
		consecutiveSendErrors = 0
		sentCount++

		p.mu.Lock()
		p.stats.onSendSuccess()
		p.mu.Unlock()

		// Start per-seq timeout timer.
		timer := time.AfterFunc(p.opts.timeout, func() {
			select {
			case <-done:
				return // shutting down, silently discard
			case timeoutCh <- seq:
			default:
				p.opts.logger.Warnf("timeout channel full for seq %d", seq)
			}
		})
		pending[seq] = &pendingEntry{timer: timer}

		if p.opts.onSend != nil {
			reqCopy := *req
			enqueueCallback(func() {
				p.opts.onSend(&reqCopy)
			})
		}

		// Stop ticker if count reached after this send.
		if p.opts.count > 0 && sentCount >= p.opts.count {
			if !tickerStopped {
				ticker.Stop()
				tickerStopped = true
			}
		}
	}

	// Send first packet immediately.
	sendOne()

	// Check for immediate fatal send error.
	if consecutiveSendErrors >= maxConsecutiveSendErrors {
		goto cleanup
	}

	// Main select loop.
	for {
		// Check if all done (count mode: all sent and no pending).
		if tickerStopped && len(pending) == 0 {
			goto cleanup
		}

		select {
		case <-ctx.Done():
			goto cleanup

		case <-ticker.C:
			if tickerStopped {
				continue
			}
			sendOne()
			if consecutiveSendErrors >= maxConsecutiveSendErrors {
				goto cleanup
			}

		case seq := <-timeoutCh:
			entry, ok := pending[seq]
			if !ok {
				// Already handled (e.g. reply arrived just before timeout fired).
				continue
			}
			entry.timer.Stop()
			delete(pending, seq)

			p.mu.Lock()
			p.stats.onTimeout()
			p.mu.Unlock()

			if p.opts.onRecvError != nil {
				reply := &EchoReply{Seq: seq}
				enqueueCallback(func() {
					p.opts.onRecvError(reply, ErrTimeout)
				})
			}

		case result := <-recvCh:
			if result.err != nil {
				// Unrecoverable receive error.
				goto cleanup
			}

			reply := result.reply
			entry, ok := pending[reply.Seq]
			if !ok {
				// Late reply: seq already timed out.
				p.mu.Lock()
				p.stats.onLateDrop()
				p.mu.Unlock()
				continue
			}

			// Valid reply within timeout window.
			entry.timer.Stop()
			delete(pending, reply.Seq)

			p.mu.Lock()
			p.stats.onReply(reply.RTT)
			p.mu.Unlock()

			if p.opts.onRecv != nil {
				replyCopy := *reply
				enqueueCallback(func() {
					p.opts.onRecv(&replyCopy)
				})
			}
		}
	}

cleanup:
	// 1. Signal recvLoop to exit (safe: done may already be closed by Stop()).
	select {
	case <-done:
		// Already closed.
	default:
		close(done)
	}
	_ = p.conn.SetReadDeadline(time.Now().Add(-time.Second))

	// 2. Wait for recvLoop to exit.
	<-recvLoopDone

	// 3. Stop all pending timers and clear pending table.
	for _, entry := range pending {
		entry.timer.Stop()
	}
	// Clear the map (let GC collect).
	for k := range pending {
		delete(pending, k)
	}

	// 4. Close callback channel and wait for dispatcher to drain.
	close(callbackCh)
	<-dispatcherDone

	// 5. Close connection.
	_ = p.conn.Close()

	// 6. Compute final statistics.
	p.mu.Lock()
	p.stats.compute()
	p.mu.Unlock()

	// Determine return error.
	if consecutiveSendErrors >= maxConsecutiveSendErrors {
		return ErrSendFailed
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// recvLoop continuously reads and parses replies, sending results to recvCh.
// Recoverable parse errors are logged and skipped; unrecoverable errors or
// done channel closure cause exit.
//
// Exit protocol: both on read error and on channel send, recvLoop checks done.
// Specifically, recvCh send uses `select { case recvCh <- result: case <-done: return }`
// to prevent deadlock when the main loop has stopped consuming recvCh during cleanup.
func (p *Pinger) recvLoop(recvCh chan<- recvResult) {
	buf := make([]byte, 1500)

	// Snapshot done channel once; it's created before recvLoop starts.
	p.mu.RLock()
	done := p.done
	p.mu.RUnlock()

	for {
		reply, err := recvEchoReply(p.conn, p.id, p.addr, p.ipv4, p.opts.privileged, buf)
		if err != nil {
			// Check if we're shutting down.
			select {
			case <-done:
				// Normal shutdown, exit silently.
				return
			default:
			}

			// Check if this is a recoverable error (parse/validation errors).
			if isRecoverableError(err) {
				p.opts.logger.Debugf("recoverable recv error: %v", err)
				continue
			}

			// Unrecoverable error: send to main loop with done protection.
			select {
			case recvCh <- recvResult{err: err}:
			case <-done:
			}
			return
		}

		// Send reply to main loop with done protection to avoid deadlock
		// during cleanup (when main loop has stopped consuming recvCh).
		select {
		case recvCh <- recvResult{reply: reply}:
		case <-done:
			return
		}
	}
}

// isRecoverableError determines if a receive error is recoverable.
// Parse errors, validation mismatches, etc. are recoverable.
// Network/connection errors are not.
func isRecoverableError(err error) bool {
	// Timeout errors from SetReadDeadline are handled by the done channel check.
	// Parse and validation errors (wrong type, ID mismatch, etc.) are recoverable.
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	// Non-network errors (parse failures, validation) are recoverable.
	return true
}
