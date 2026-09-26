package main

import (
	"reflect"
	"testing"
)

func testZoneA(name string, address uint32) dnsRR {
	return &dnsRR_A{Hdr: dnsRR_Header{Name: name, Rrtype: dnsTypeA, Class: dnsClassINET}, A: address}
}

func testZoneCNAME(name, target string) dnsRR {
	return &dnsRR_CNAME{Hdr: dnsRR_Header{Name: name, Rrtype: dnsTypeCNAME, Class: dnsClassINET}, Cname: target}
}

func TestZoneAnswer(t *testing.T) {
	soa := &dnsRR_SOA{Hdr: dnsRR_Header{Name: "example.", Rrtype: dnsTypeSOA, Class: dnsClassINET}, Ns: "ns.example.", Mbox: "hostmaster.example."}
	soaDetail := []string{"example.", "ns.example.", "hostmaster.example."}
	tests := []struct {
		name   string
		rcode  int
		answer []dnsRR
		ns     []dnsRR
		status string
		detail []string
	}{
		{name: "direct A", answer: []dnsRR{testZoneA("source.example.", 0xc0000201)}, status: zoneStatusInZone, detail: []string{"192.0.2.1"}},
		{name: "unordered mixed-case CNAME chain", answer: []dnsRR{
			testZoneA("target.example.", 0xc0000202),
			testZoneCNAME("HOP.example.", "TARGET.example."),
			testZoneA("unrelated.example.", 0xcb007101),
			testZoneCNAME("SOURCE.example.", "hop.example."),
		}, status: zoneStatusInZone, detail: []string{"192.0.2.2"}},
		{name: "CNAME without target address", answer: []dnsRR{testZoneCNAME("source.example.", "missing.example."), testZoneA("unrelated.example.", 0xcb007101)}, status: zoneStatusNoData, detail: []string{}},
		{name: "CNAME loop", answer: []dnsRR{testZoneCNAME("source.example.", "hop.example."), testZoneCNAME("hop.example.", "source.example.")}, status: zoneStatusError, detail: []string{"CNAME loop"}},
		{name: "CNAME target NXDOMAIN", rcode: dnsRcodeNameError, answer: []dnsRR{testZoneCNAME("source.example.", "missing.example.")}, ns: []dnsRR{soa}, status: zoneStatusNXDomain, detail: soaDetail},
		{name: "authoritative NODATA", ns: []dnsRR{soa}, status: zoneStatusNoData, detail: soaDetail},
		{name: "authoritative NXDOMAIN without RA", rcode: dnsRcodeNameError, ns: []dnsRR{soa}, status: zoneStatusNXDomain, detail: soaDetail},
		{name: "parent zone referral", ns: []dnsRR{&dnsRR_NS{Hdr: dnsRR_Header{Name: "source.example.", Rrtype: dnsTypeNS, Class: dnsClassINET}, Ns: "ns.example."}}, status: zoneStatusDelegated, detail: []string{"ns.example."}},
		{name: "AAAA through CNAME", answer: []dnsRR{testZoneCNAME("source.example.", "target.example."), &dnsRR_AAAA{Hdr: dnsRR_Header{Name: "target.example.", Rrtype: dnsTypeAAAA, Class: dnsClassINET}, AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}}, status: zoneStatusInZone, detail: []string{"2001:db8::1"}},
		{name: "SERVFAIL never trusts partial answers", rcode: dnsRcodeServerFailure, answer: []dnsRR{testZoneCNAME("source.example.", "target.example."), testZoneA("target.example.", 0xc0000202)}, status: "SERVFAIL", detail: []string{}},
		{name: "REFUSED", rcode: dnsRcodeRefused, status: "REFUSED", detail: []string{}},
		{name: "unrelated address", answer: []dnsRR{testZoneA("unrelated.example.", 0xcb007101)}, status: zoneStatusNoData, detail: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := &dnsMsg{dnsMsgHdr: dnsMsgHdr{id: 42, response: true, rcode: tt.rcode}, question: []dnsQuestion{{Name: "source.example.", Qtype: dnsTypeA, Qclass: dnsClassINET}}, answer: tt.answer, ns: tt.ns}
			packet, ok := message.Pack()
			if !ok {
				t.Fatal("failed to pack DNS fixture")
			}
			domain, id, status, detail := unpackDnsZone(packet)
			if domain != "source.example." || id != 42 || status != tt.status || !reflect.DeepEqual(detail, tt.detail) {
				t.Fatalf("got (%q, %d, %q, %v), want original domain/id, %q, %v", domain, id, status, detail, tt.status, tt.detail)
			}
		})
	}
}
