//go:build unix

package ping

import (
	"math"
	"time"
)

// Statistics holds the aggregated results of a ping session.
// Mean and variance are tracked online via Welford's algorithm.
type Statistics struct {
	Addr      string
	Sent      int
	TxError   int
	Received  int
	Timeout   int
	LateDrop  int
	Loss      float64
	MinRTT    time.Duration
	MaxRTT    time.Duration
	AvgRTT    time.Duration
	StdDevRTT time.Duration

	n    int
	mean float64
	m2   float64
}

func (s *Statistics) onReply(rtt time.Duration) {
	s.Received++
	ns := float64(rtt.Nanoseconds())

	// Welford's online algorithm for mean and variance.
	s.n++
	delta := ns - s.mean
	s.mean += delta / float64(s.n)
	s.m2 += delta * (ns - s.mean)

	if s.n == 1 || rtt < s.MinRTT {
		s.MinRTT = rtt
	}
	if rtt > s.MaxRTT {
		s.MaxRTT = rtt
	}
}

func (s *Statistics) finalize() {
	if s.Sent > 0 {
		s.Loss = 1.0 - float64(s.Received)/float64(s.Sent)
		if s.Loss < 0 {
			s.Loss = 0
		}
	}

	if s.n > 0 {
		s.AvgRTT = time.Duration(s.mean)
		variance := s.m2 / float64(s.n)
		if variance > 0 {
			s.StdDevRTT = time.Duration(math.Sqrt(variance))
		}
	}
}
