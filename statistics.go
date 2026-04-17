//go:build linux

package ping

import (
	"math"
	"time"
)

// Statistics holds the aggregated results of a ping session.
type Statistics struct {
	Addr      string        // Target address
	Attempts  int           // Total send attempts (including failures)
	Sent      int           // Successfully sent count
	TxError   int           // Send failure count
	Received  int           // Replies received within timeout window
	Timeout   int           // Per-seq timeout count
	LateDrop  int           // Late replies dropped after timeout
	Loss      float64       // Network loss rate: 1 - Received/Sent (0 when Sent==0)
	MinRTT    time.Duration // Minimum RTT
	MaxRTT    time.Duration // Maximum RTT
	AvgRTT    time.Duration // Average RTT
	StdDevRTT time.Duration // RTT standard deviation

	// Internal accumulators for Welford's online algorithm.
	rttSum   float64 // sum of RTT in nanoseconds
	rttSqr   float64 // sum of squared RTT in nanoseconds
	rttCount int     // number of RTT samples (== Received)
}

// newStatistics creates and initializes a Statistics for the given target address.
func newStatistics(addr string) *Statistics {
	return &Statistics{
		Addr: addr,
	}
}

// onSendAttempt records a send attempt (called before each send, regardless of outcome).
func (s *Statistics) onSendAttempt() {
	s.Attempts++
}

// onSendSuccess records a successful send.
func (s *Statistics) onSendSuccess() {
	s.Sent++
}

// onSendError records a send failure.
func (s *Statistics) onSendError() {
	s.TxError++
}

// onReply records a successful reply and updates RTT accumulators.
func (s *Statistics) onReply(rtt time.Duration) {
	s.Received++

	ns := float64(rtt.Nanoseconds())
	s.rttSum += ns
	s.rttSqr += ns * ns
	s.rttCount++

	if s.rttCount == 1 || rtt < s.MinRTT {
		s.MinRTT = rtt
	}
	if rtt > s.MaxRTT {
		s.MaxRTT = rtt
	}
}

// onTimeout records a per-seq timeout event.
func (s *Statistics) onTimeout() {
	s.Timeout++
}

// onLateDrop records a late reply that arrived after its seq had already timed out.
func (s *Statistics) onLateDrop() {
	s.LateDrop++
}

// compute calculates AvgRTT, StdDevRTT, and Loss from accumulated values.
// Called once before Run returns.
func (s *Statistics) compute() {
	if s.Sent > 0 {
		s.Loss = 1.0 - float64(s.Received)/float64(s.Sent)
		if s.Loss < 0 {
			s.Loss = 0
		}
	}

	if s.rttCount > 0 {
		avg := s.rttSum / float64(s.rttCount)
		s.AvgRTT = time.Duration(avg)

		variance := s.rttSqr/float64(s.rttCount) - avg*avg
		if variance < 0 {
			variance = 0
		}
		s.StdDevRTT = time.Duration(math.Sqrt(variance))
	}
}
