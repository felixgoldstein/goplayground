package main

import (
	"fmt"
	"os"
)

func unpackDns(msg []byte, dnsType uint16) (domain string, id uint16, ips []string) {
	d := new(dnsMsg)
	if !d.Unpack(msg) {
		// fmt.Fprintf(os.Stderr, "dns error (unpacking)\n")
		ips = []string{"ERROR: dns error (unpacking)"}
		return
	}

	id = d.id

	if len(d.question) < 1 {
		// fmt.Fprintf(os.Stderr, "dns error (wrong question section)\n")
		ips = []string{"ERROR: dns error (wrong question section)"}
		return
	}

	domain = d.question[0].Name
	if len(domain) < 1 {
		// fmt.Fprintf(os.Stderr, "dns error (wrong domain in question)\n")
		ips = []string{"ERROR: dns error (wrong domain in question)"}
		return
	}

	_, addrs, err := answer(domain, "server", d, dnsType)

	if err != nil {
		// fmt.Fprintf(os.Stderr, "answer: %v\n", err)
		ips = []string{fmt.Sprintf("ERROR: Answer from name server: \"%v\"", err)}
	}

	if err == nil {
		switch (dnsType) {
		case dnsTypeA:
			ips = convertRR_A(addrs)
		case dnsTypeAAAA:
			ips = convertRR_AAAA(addrs)
		case dnsTypeTXT:
			ips = convertRR_TXT(addrs)
		case dnsTypeNS:
			ips = convertRR_NS(addrs)
		}
	}

	return
}

func packDns(domain string, id uint16, dnsType uint16) []byte {

	out := new(dnsMsg)
	out.id = id
	out.recursion_desired = true
	out.question = []dnsQuestion{
		{domain, dnsType, dnsClassINET},
	}

	msg, ok := out.Pack()
	if !ok {
		fmt.Fprintf(os.Stderr, "can't pack domain %s\n", domain)
		os.Exit(1)
	}
	return msg
}
