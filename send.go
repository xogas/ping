//go:build unix

package ping

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// timestampLen is the number of bytes used to encode the send timestamp
	// in the ICMP payload (nanosecond Unix time, big-endian).
	timestampLen = 8

	// payloadFillByte is the fill pattern for bytes beyond the timestamp.
	payloadFillByte = 0xAA
)

// EchoRequest represents an outgoing ICMP Echo Request.
type EchoRequest struct {
	ID   int
	Seq  uint16
	Size int
	Sent time.Time
}

// sendEchoRequest constructs and sends an ICMP Echo Request.
// req.Sent is set to the current time as a side effect.
func sendEchoRequest(conn *packetConn, dst net.Addr, req *EchoRequest) error {
	req.Sent = time.Now()

	payload := buildPayload(req.Size, req.Sent)
	b, err := buildICMPMessage(conn.ipv4, req, payload)
	if err != nil {
		return err
	}

	_, err = conn.WriteTo(b, dst)
	return err
}

func buildICMPMessage(isIPv4 bool, req *EchoRequest, payload []byte) ([]byte, error) {
	var msgType icmp.Type
	if isIPv4 {
		msgType = ipv4.ICMPTypeEcho
	} else {
		msgType = ipv6.ICMPTypeEchoRequest
	}

	// Marshal with a nil *icmp.PacketConn --- the PSH flag is only relevant
	// for IPv4 raw sockets and our Echo body does not require a connection.
	msg := &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   req.ID,
			Seq:  int(req.Seq),
			Data: payload,
		},
	}

	return msg.Marshal(nil)
}

func buildPayload(size int, sentAt time.Time) []byte {
	if size < 0 {
		size = 0
	}
	payload := make([]byte, size)

	// First timestampLen bytes: send timestamp (nanosecond Unix, big-endian).
	if size >= timestampLen {
		binary.BigEndian.PutUint64(payload[:timestampLen], uint64(sentAt.UnixNano()))
	}

	// Remaining bytes: fixed fill pattern.
	for i := timestampLen; i < size; i++ {
		payload[i] = payloadFillByte
	}

	return payload
}
