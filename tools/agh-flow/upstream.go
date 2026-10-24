package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// answer is one scripted upstream reply.
type answer struct {
	rcode int
	rrs   []dns.RR
}

type scriptKey struct {
	name  string
	qtype uint16
}

// parseScript reads the [upstream] section:
//
//	Q name TYPE
//	RCODE NXDOMAIN        (optional, default NOERROR)
//	owner. ttl IN TYPE rdata   (answer section, master file syntax)
func parseScript(text string) map[scriptKey]*answer {
	script := map[scriptKey]*answer{}
	var cur *answer
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Q "):
			fields := strings.Fields(line)
			if len(fields) != 3 {
				fatal("bad upstream line %q", line)
			}

			qtype, ok := dns.StringToType[strings.ToUpper(fields[2])]
			if !ok {
				fatal("bad type in %q", line)
			}

			cur = &answer{}
			script[scriptKey{strings.ToLower(dns.Fqdn(fields[1])), qtype}] = cur
		case strings.HasPrefix(line, "RCODE "):
			rcode, ok := dns.StringToRcode[strings.TrimSpace(strings.TrimPrefix(line, "RCODE "))]
			if !ok || cur == nil {
				fatal("bad line %q", line)
			}

			cur.rcode = rcode
		default:
			rr, err := dns.NewRR(line)
			if err != nil || cur == nil {
				fatal("bad record %q: %v", line, err)
			}

			cur.rrs = append(cur.rrs, rr)
		}
	}

	return script
}

// serveUpstream answers on UDP and TCP from the script. A question that is not
// scripted gets REFUSED and is reported, because AdGuard Home should have
// answered it itself.
func serveUpstream(port int, script map[scriptKey]*answer, passthrough bool) (stop func()) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true

		if len(req.Question) != 1 {
			resp.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(resp)

			return
		}

		q := req.Question[0]
		ans, ok := script[scriptKey{strings.ToLower(q.Name), q.Qtype}]
		if !ok && passthrough {
			_ = w.WriteMsg(passthroughReply(resp, q))

			return
		}

		if !ok {
			fmt.Fprintf(os.Stderr, "agh-flow: unscripted upstream question %s %s\n", q.Name, dns.TypeToString[q.Qtype])
			resp.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(resp)

			return
		}

		resp.Rcode = ans.rcode
		for _, rr := range ans.rrs {
			resp.Answer = append(resp.Answer, dns.Copy(rr))
		}

		_ = w.WriteMsg(resp)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	started := make(chan struct{}, 2)
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { check(udp.ListenAndServe()) }()
	go func() { check(tcp.ListenAndServe()) }()
	<-started
	<-started

	return func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	}
}

// passthroughTTL marks a reply that came from the upstream; AdGuard Home's own
// blocked replies use the 10 s blocked TTL.
const passthroughTTL = 300

// passthroughReply is the generic upstream answer of the decisions mode.
func passthroughReply(resp *dns.Msg, q dns.Question) *dns.Msg {
	hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: passthroughTTL}
	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = []dns.RR{&dns.A{Hdr: hdr, A: []byte{198, 51, 100, 200}}}
	case dns.TypeAAAA:
		resp.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8:ffff::200")}}
	case dns.TypeHTTPS:
		resp.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{Hdr: hdr, Priority: 1, Target: "."}}}
	case dns.TypeTXT:
		resp.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"x"}}}
	default:
		soaHdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: passthroughTTL}
		resp.Ns = []dns.RR{&dns.SOA{Hdr: soaHdr, Ns: "ns.upstream.invalid.", Mbox: "hostmaster.upstream.invalid.", Serial: 1}}
	}

	return resp
}
