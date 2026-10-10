package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
)

func TestPackDnsAdvertisesEDNS(t *testing.T) {
	msg := packDns("example.de.", 7, dnsTypeTXT)

	if arcount := binary.BigEndian.Uint16(msg[10:12]); arcount != 1 {
		t.Fatalf("additional count = %d, want 1", arcount)
	}
	// Root name, type OPT, class = UDP size, TTL 0, no RDATA.
	want := []byte{0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0}
	if got := msg[len(msg)-len(want):]; !bytes.Equal(got, want) {
		t.Fatalf("OPT record = % x, want % x", got, want)
	}

	d := new(dnsMsg)
	if !d.Unpack(msg) || d.question[0].Name != "example.de." || d.question[0].Qtype != dnsTypeTXT {
		t.Fatalf("query with OPT record does not round-trip: %+v", d)
	}
}

func TestIsTruncated(t *testing.T) {
	for _, truncated := range []bool{true, false} {
		reply := &dnsMsg{dnsMsgHdr: dnsMsgHdr{id: 1, response: true, truncated: truncated}, question: []dnsQuestion{{"example.de.", dnsTypeTXT, dnsClassINET}}}
		msg, _ := reply.Pack()
		if isTruncated(msg) != truncated {
			t.Fatalf("isTruncated = %v, want %v", !truncated, truncated)
		}
	}
	if isTruncated([]byte{1, 2}) {
		t.Fatal("a short packet is not a truncated reply")
	}
}

func testTXT(name, value string) dnsRR {
	return &dnsRR_TXT{Hdr: dnsRR_Header{Name: name, Rrtype: dnsTypeTXT, Class: dnsClassINET}, Txt: value}
}

// serveTCP answers one framed query on a local listener with the given records.
func serveTCP(t *testing.T, answer []dnsRR) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		id, question, ok := parseQuestion(query)
		if !ok {
			return
		}
		reply := &dnsMsg{dnsMsgHdr: dnsMsgHdr{id: id, response: true, recursion_available: true}, question: []dnsQuestion{question}, answer: answer}
		msg, _ := reply.Pack()
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
		conn.Write(append(framed, msg...))
	}()

	return listener.Addr().String()
}

func useServer(t *testing.T, server string, asTXT bool) {
	t.Helper()
	previousServer, previousTXT := dnsServer, txt
	dnsServer, txt = server, asTXT
	t.Cleanup(func() { dnsServer, txt = previousServer, previousTXT })
}

func truncatedTXTReply(t *testing.T) []byte {
	t.Helper()
	reply := &dnsMsg{dnsMsgHdr: dnsMsgHdr{id: 4711, response: true, truncated: true, recursion_available: true}, question: []dnsQuestion{{"007007.de.", dnsTypeTXT, dnsClassINET}}}
	msg, ok := reply.Pack()
	if !ok {
		t.Fatal("failed to pack the truncated reply")
	}
	return msg
}

func TestTruncatedReplyIsAskedAgainOverTCP(t *testing.T) {
	useServer(t, serveTCP(t, []dnsRR{
		testTXT("007007.de.", "afternic-verification-VWeELqNpVSoxWEv3yDB7bw"),
		testTXT("007007.de.", "dba1cdfcf6359389d170caadb3223ad2.elitedomains.de"),
	}), true)

	got := answerOverTCP(truncatedTXTReply(t))

	want := &domainAnswer{4711, "007007.de.", []string{"afternic-verification-VWeELqNpVSoxWEv3yDB7bw", "dba1cdfcf6359389d170caadb3223ad2.elitedomains.de"}, ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFailedTCPRetryIsReportedAsError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	listener.Close()
	useServer(t, closed, true)

	got := answerOverTCP(truncatedTXTReply(t))

	if got.id != 4711 || got.domain != "007007.de." || len(got.ips) != 1 || !bytes.HasPrefix([]byte(got.ips[0]), []byte("ERROR: truncated UDP reply, TCP retry failed")) {
		t.Fatalf("got %+v, want an ERROR answer for 007007.de.", got)
	}
}
