// Command agh-oracle prints the block/pass decision AdGuard Home v0.107.79
// (urlfilter v0.23.4) makes for host names, and the answer its default blocking
// mode would give.
//
// It is a development tool for generating golden files. It is GPL-3.0 and is
// never linked into picoguard.
//
// Usage:
//
//	agh-oracle [-list FILE]... [-user FILE] [-allow FILE]... [-q FILE]
//	agh-oracle sample -seed N -n COUNT FILE...
//
// Query lines are "input checktype [querytype]". checktype is the record type
// being checked against the rules (the query type for request filtering, CNAME,
// A, AAAA or HTTPS for answer records). querytype is the type of the original
// question and decides the shape of a blocked answer; it defaults to
// checktype. Output lines repeat the query fields followed by "pass -" or
// "block ANSWER". ANSWER is a comma separated IP list, "empty" (NOERROR without
// records) or "nodata" (NOERROR with the fake SOA).
package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)

	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "sample" {
		runSample(os.Args[2:])

		return
	}

	var lists, allows multiFlag
	var user, queries string
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			fatal("flag %s needs a value", args[i])
		}

		v := args[i+1]
		switch args[i] {
		case "-list":
			lists = append(lists, v)
		case "-allow":
			allows = append(allows, v)
		case "-user":
			user = v
		case "-q":
			queries = v
		default:
			fatal("unknown flag %s", args[i])
		}

		i++
	}

	main, allow := buildEngines(lists, user, allows)

	in := io.Reader(os.Stdin)
	if queries != "" {
		f, err := os.Open(queries)
		if err != nil {
			fatal("%v", err)
		}
		defer f.Close()

		in = f
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 {
			fatal("bad query line %q", line)
		}

		check := rrType(fields[1])
		orig := check
		if len(fields) == 3 {
			orig = rrType(fields[2])
		}

		pass, answer := decide(main, allow, fields[0], check, orig)
		if pass {
			fmt.Fprintf(out, "%s pass -\n", line)
		} else {
			fmt.Fprintf(out, "%s block %s\n", line, answer)
		}
	}

	if err := sc.Err(); err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "agh-oracle: "+format+"\n", args...)
	os.Exit(1)
}

func rrType(name string) uint16 {
	t, ok := dns.StringToType[strings.ToUpper(name)]
	if !ok {
		fatal("unknown record type %q", name)
	}

	return t
}

func readFile(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		fatal("%v", err)
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			fatal("%s: %v", path, err)
		}
		defer gz.Close()

		r = gz
	}

	data, err := io.ReadAll(r)
	if err != nil {
		fatal("%s: %v", path, err)
	}

	return data
}

// buildEngines mirrors AdGuard Home's initFiltering: the user rules come
// first, then the filter lists, all scanned with cosmetic rules ignored; the
// allowlists go to a second engine.
func buildEngines(lists []string, user string, allows []string) (main, allow *urlfilter.DNSEngine) {
	var blockLists []filterlist.Interface
	id := rules.ListID(1)
	if user != "" {
		blockLists = append(blockLists, filterlist.NewBytes(&filterlist.BytesConfig{
			ID: id, RulesText: readFile(user), IgnoreCosmetic: true,
		}))
		id++
	}

	for _, p := range lists {
		blockLists = append(blockLists, filterlist.NewBytes(&filterlist.BytesConfig{
			ID: id, RulesText: readFile(p), IgnoreCosmetic: true,
		}))
		id++
	}

	var allowLists []filterlist.Interface
	for _, p := range allows {
		allowLists = append(allowLists, filterlist.NewBytes(&filterlist.BytesConfig{
			ID: id, RulesText: readFile(p), IgnoreCosmetic: true,
		}))
		id++
	}

	blockStorage, err := filterlist.NewRuleStorage(blockLists)
	if err != nil {
		fatal("%v", err)
	}

	allowStorage, err := filterlist.NewRuleStorage(allowLists)
	if err != nil {
		fatal("%v", err)
	}

	return urlfilter.NewDNSEngine(blockStorage), urlfilter.NewDNSEngine(allowStorage)
}

// decide re-expresses DNSFilter.matchHost (filtering.go) and the blocked
// message construction of genDNSFilterMessage (msg.go). DNS rewrites are out of
// scope for picoguard, so a rewrite result is not modeled.
func decide(
	main, allow *urlfilter.DNSEngine,
	host string,
	check, orig uint16,
) (pass bool, answer string) {
	host = strings.ToLower(host)
	req := &urlfilter.DNSRequest{Hostname: host, DNSType: check}

	if _, ok := allow.MatchRequest(req); ok {
		return true, ""
	}

	res, matched := main.MatchRequest(req)
	if !matched {
		return true, ""
	}

	var ips []netip.Addr
	switch {
	case res.NetworkRule != nil:
		if res.NetworkRule.Whitelist {
			return true, ""
		}
	case check == dns.TypeA && res.HostRulesV4 != nil:
		ips = uniqueIPs(res.HostRulesV4)
	case check == dns.TypeAAAA && res.HostRulesV6 != nil:
		ips = uniqueIPs(res.HostRulesV6)
	default:
		// hostResultForOtherQType: blocked, no result IPs.
	}

	return false, blockedAnswer(orig, ips)
}

func uniqueIPs(hostRules []*rules.HostRule) (ips []netip.Addr) {
	for _, hr := range hostRules {
		ip := hr.IP.WithZone("")
		if ip == (netip.Addr{}) {
			continue
		}

		dup := false
		for _, have := range ips {
			if have == ip {
				dup = true
			}
		}

		if !dup {
			ips = append(ips, ip)
		}
	}

	return ips
}

func blockedAnswer(qt uint16, ips []netip.Addr) string {
	if qt != dns.TypeA && qt != dns.TypeAAAA && qt != dns.TypeHTTPS {
		return "nodata"
	}

	if len(ips) == 0 {
		switch qt {
		case dns.TypeA:
			ips = []netip.Addr{netip.IPv4Unspecified()}
		case dns.TypeAAAA:
			ips = []netip.Addr{netip.IPv6Unspecified()}
		}
	}

	var out []string
	switch qt {
	case dns.TypeA:
		for _, ip := range ips {
			if !ip.Is4() {
				return "empty"
			}

			out = append(out, ip.String())
		}
	case dns.TypeAAAA:
		for _, ip := range ips {
			if ip.Is6() {
				out = append(out, ip.String())
			}
		}
	}

	if len(out) == 0 {
		return "empty"
	}

	return strings.Join(out, ",")
}
