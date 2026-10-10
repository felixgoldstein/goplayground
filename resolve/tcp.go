package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// A reply that does not fit into one UDP datagram comes back with the TC bit
// set and the answer section dropped. Read as a normal reply, that is a name
// without records: a TXT set of a dozen verification strings was reported as
// "no such host" (ED-803). EDNS0 (see packDns) raises the limit from 512 to
// ednsUDPSize bytes; whatever is still larger is asked again over TCP, which
// has no size limit.

// ednsUDPSize is the UDP payload size advertised through EDNS0. 1232 bytes is
// the DNS Flag Day 2020 value: large enough for nearly every reply, small
// enough to avoid IP fragmentation.
const ednsUDPSize = 1232

const tcpTimeout = 5 * time.Second

// tcpSlots caps concurrent TCP lookups; the UDP side may produce truncated
// replies at the full packet rate.
var tcpSlots = make(chan struct{}, 32)

func isTruncated(msg []byte) bool {
	return len(msg) >= 4 && binary.BigEndian.Uint16(msg[2:4])&_TC != 0
}

// parseQuestion reads the id and question of a reply without touching its
// record sections, which a truncated reply may carry only in part.
func parseQuestion(msg []byte) (id uint16, question dnsQuestion, ok bool) {
	var dh dnsHeader
	off, ok := unpackStruct(&dh, msg, 0)
	if !ok || dh.Qdcount < 1 {
		return 0, question, false
	}
	if _, ok = unpackStruct(&question, msg, off); !ok || question.Name == "" {
		return 0, question, false
	}
	return dh.Id, question, true
}

// answerOverTCP repeats the question of a truncated UDP reply over TCP.
func answerOverTCP(truncated []byte) *domainAnswer {
	id, question, ok := parseQuestion(truncated)
	if !ok {
		return decodeAnswer(truncated)
	}

	reply, err := exchangeTCP(packDns(question.Name, id, question.Qtype), id)
	if err != nil {
		detail := fmt.Sprintf("truncated UDP reply, TCP retry failed: %v", err)
		if zoneCheck {
			return &domainAnswer{id, question.Name, []string{detail}, zoneStatusError}
		}
		return &domainAnswer{id, question.Name, []string{"ERROR: " + detail}, ""}
	}

	return decodeAnswer(reply)
}

// exchangeTCP sends one query to dnsServer over TCP and returns its reply.
func exchangeTCP(query []byte, id uint16) ([]byte, error) {
	tcpSlots <- struct{}{}
	defer func() { <-tcpSlots }()

	conn, err := net.DialTimeout("tcp", dnsServer, tcpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(tcpTimeout))

	// Over TCP every message is preceded by its length (RFC 1035 4.2.2).
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}

	if len(reply) < 2 || binary.BigEndian.Uint16(reply[:2]) != id {
		return nil, errors.New("reply id does not match the query")
	}
	return reply, nil
}
