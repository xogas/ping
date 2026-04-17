//go:build linux

package ping

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// EchoRequest represents an outgoing ICMP Echo Request.
type EchoRequest struct {
	ID   int       // ICMP Identifier
	Seq  uint16    // ICMP Sequence Number (16-bit, wraps around)
	Size int       // Payload size in bytes
	Sent time.Time // Send timestamp (recorded on success; attempt time on failure)
}

// sendEchoRequest constructs and sends an ICMP Echo Request.
// It records req.Sent = time.Now(), builds the payload (with timestamp in first 8 bytes),
// serializes the ICMP message, and sends it via conn.
func sendEchoRequest(conn packetConn, dst net.Addr, req *EchoRequest, ipv4Flag bool) error {
	req.Sent = time.Now()

	payload := buildPayload(req.Size, req.Sent)

	var msgType icmp.Type
	if ipv4Flag {
		msgType = ipv4.ICMPTypeEcho
	} else {
		msgType = ipv6.ICMPTypeEchoRequest
	}

	msg := &icmp.Message{
		Type: msgType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   req.ID,
			Seq:  int(req.Seq),
			Data: payload,
		},
	}

	var proto int
	if ipv4Flag {
		proto = 1 // IANA ICMP
	} else {
		proto = 58 // IANA ICMPv6
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	// For non-privileged mode, the checksum is handled by the kernel.
	_ = proto

	_, err = conn.WriteTo(b, dst)
	return err
}

// buildPayload generates a payload of the specified size.
// The first 8 bytes encode the sentAt timestamp (UnixNano, big-endian).
// Remaining bytes are filled with a fixed pattern (0xAA).
func buildPayload(size int, sentAt time.Time) []byte {
	if size < 0 {
		size = 0
	}
	payload := make([]byte, size)

	// Encode timestamp in the first 8 bytes if there's room.
	if size >= 8 {
		binary.BigEndian.PutUint64(payload[:8], uint64(sentAt.UnixNano()))
	}

	// Fill remaining bytes with a fixed pattern.
	for i := 8; i < size; i++ {
		payload[i] = 0xAA
	}

	return payload
}
