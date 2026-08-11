package main

// Zone delegation check (-zone).
//
// The default mode of this tool answers "which records does this name have",
// and folds every kind of failure into a single "no such host" error string.
// That is not enough to tell "this name is not in the parent zone" apart from
// "this name has no records" or "the server broke" — a distinction the .de
// hold detection depends on.
//
// This mode reports the rcode verbatim instead, reads the delegation out of
// the authority section (so it also works when asking a registry nameserver
// directly, which answers referrals rather than final answers), and hands back
// the SOA of whichever zone produced a negative answer. That SOA is what
// proves the negative came from the registry itself.
//
// Everything here is additive: nothing in this file runs unless -zone is set.

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

const (
	zoneStatusDelegated = "DELEGATED"
	zoneStatusInZone    = "INZONE"
	zoneStatusNXDomain  = "NXDOMAIN"
	zoneStatusNoData    = "NODATA"
	zoneStatusError     = "ERROR"
)

// rcodeName maps an rcode to its mnemonic so callers can branch on a stable
// token instead of a bare number.
func rcodeName(rcode int) string {
	switch rcode {
	case dnsRcodeFormatError:
		return "FORMERR"
	case dnsRcodeServerFailure:
		return "SERVFAIL"
	case dnsRcodeNotImplemented:
		return "NOTIMP"
	case dnsRcodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// zoneAnswer classifies a response as delegated / not delegated and returns the
// supporting records: the nameserver set for a delegation, the SOA fields for a
// negative answer.
func zoneAnswer(dns *dnsMsg) (status string, detail []string) {
	name := dns.question[0].Name

	// A delegation surfaces as NS records owned by the queried name. A
	// recursive resolver puts them in the answer section; a parent-zone
	// nameserver returns them as a referral in the authority section, which
	// is why both are searched.
	ns := make([]string, 0, 8)
	for _, section := range [][]dnsRR{dns.answer, dns.ns} {
		for _, rr := range section {
			rec, ok := rr.(*dnsRR_NS)
			if !ok {
				continue
			}
			h := rec.Header()
			if h.Class == dnsClassINET && h.Name == name {
				ns = append(ns, rec.Ns)
			}
		}
	}

	if len(ns) > 0 {
		sort.Strings(ns)
		return zoneStatusDelegated, ns
	}

	// No delegation, but the name may still carry addresses. DENIC lets a
	// domain live in the zone through its own A/AAAA entries instead of a
	// delegation, and such a name resolves perfectly well — so finding
	// addresses here rules a hold out just as a delegation does. Without this
	// branch every one of those domains would land in NODATA and be
	// indistinguishable from a name that carries nothing at all.
	addrs := make([]string, 0, 8)
	for _, rr := range dns.answer {
		h := rr.Header()
		if h.Class != dnsClassINET || h.Name != name {
			continue
		}

		switch rec := rr.(type) {
		case *dnsRR_A:
			addrs = append(addrs, fmt.Sprintf("%d.%d.%d.%d",
				rec.A>>24, (rec.A>>16)&0xFF, (rec.A>>8)&0xFF, rec.A&0xFF))
		case *dnsRR_AAAA:
			addrs = append(addrs, net.IP(rec.AAAA[:]).String())
		}
	}

	if len(addrs) > 0 {
		sort.Strings(addrs)
		return zoneStatusInZone, addrs
	}

	// Nothing at all, so the interesting part is who said so. The authority
	// SOA names the zone that answered plus its primary and its contact —
	// for .de that is "de. f.nic.de. dns-operations.denic.de.", which lets
	// the caller confirm DENIC answered rather than something in between.
	soa := make([]string, 0, 3)
	for _, rr := range dns.ns {
		rec, ok := rr.(*dnsRR_SOA)
		if !ok {
			continue
		}
		soa = append(soa, rec.Header().Name, rec.Ns, rec.Mbox)
		break
	}

	switch dns.rcode {
	case dnsRcodeNameError:
		// Deliberately not gated on recursion_available the way answer()
		// gates it: an authoritative server never sets RA, so requiring it
		// would misreport every registry NXDOMAIN as a protocol error.
		return zoneStatusNXDomain, soa
	case dnsRcodeSuccess:
		return zoneStatusNoData, soa
	}

	return rcodeName(dns.rcode), soa
}

// unpackDnsZone is the -zone counterpart to unpackDns.
func unpackDnsZone(msg []byte) (domain string, id uint16, status string, detail []string) {
	d := new(dnsMsg)
	if !d.Unpack(msg) {
		return "", 0, zoneStatusError, []string{"unpacking failed"}
	}

	id = d.id

	if len(d.question) < 1 || len(d.question[0].Name) < 1 {
		return "", id, zoneStatusError, []string{"wrong question section"}
	}

	domain = d.question[0].Name
	status, detail = zoneAnswer(d)

	return domain, id, status, detail
}

// formatZoneLine renders one -zone result row: domain,STATUS,supporting records.
func formatZoneLine(domain, status string, detail []string) string {
	return domain + "," + status + "," + strings.Join(detail, " ")
}
