package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"

	"github.com/AdguardTeam/urlfilter/rules"
)

// validName keeps sampled names to plain host names and IP literals that a DNS client can send.
var validName = regexp.MustCompile(`^[a-z0-9_:-]{1,63}(\.[a-z0-9_:-]{1,63})*$`)

// runSample prints sampled queries for the given rule files: names built from
// block rules, subdomains, allow rules, regex rules, rules with modifiers,
// host rules, random names that match nothing and IP address inputs.
//
//	agh-oracle sample -seed N -n COUNT FILE...
func runSample(args []string) {
	seed, count := int64(1), 1000
	var files []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-seed":
			i++
			seed, _ = strconv.ParseInt(args[i], 10, 64)
		case "-n":
			i++
			count, _ = strconv.Atoi(args[i])
		default:
			files = append(files, args[i])
		}
	}

	rng := rand.New(rand.NewSource(seed))

	var plain, allow, regex, modifier, wildcard, host []string
	for _, p := range files {
		sc := bufio.NewScanner(strings.NewReader(string(readFile(p))))
		sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			r, err := rules.NewRule(line, 1)
			if err != nil || r == nil {
				continue
			}

			switch r := r.(type) {
			case *rules.HostRule:
				host = append(host, r.Hostnames...)
			case *rules.NetworkRule:
				if !r.IsHostLevelNetworkRule() {
					continue
				}

				text := r.Text()
				name := nameFromRule(text)
				switch {
				case r.IsRegexRule():
					if name := nameFromRegex(strings.TrimPrefix(text, "@@")); name != "" {
						regex = append(regex, name)
					}
				case name == "":
				case strings.Contains(text, "$"):
					modifier = append(modifier, name)
				case strings.Contains(strings.TrimPrefix(text, "@@"), "*"):
					wildcard = append(wildcard, strings.ReplaceAll(name, "*", "abc"))
				case r.Whitelist:
					allow = append(allow, name)
				default:
					plain = append(plain, name)
				}
			}
		}
	}

	types := []string{"A", "A", "A", "A", "A", "A", "AAAA", "AAAA", "AAAA", "HTTPS", "TXT", "MX", "CNAME"}
	pick := func(from []string) string {
		if len(from) == 0 {
			return ""
		}

		return from[rng.Intn(len(from))]
	}
	label := func() string {
		const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, 3+rng.Intn(8))
		for i := range b {
			b[i] = letters[rng.Intn(len(letters))]
		}

		return string(b)
	}

	seen := map[string]bool{}
	var out []string
	emit := func(name string) {
		if !validName.MatchString(name) {
			return
		}

		q := name + " " + types[rng.Intn(len(types))]
		if !seen[q] {
			seen[q] = true
			out = append(out, q)
		}
	}

	for len(out) < count {
		switch n := rng.Intn(100); {
		case n < 18:
			emit(pick(plain))
		case n < 36:
			emit(label() + "." + pick(plain))
		case n < 44:
			emit(pick(allow))
		case n < 50:
			emit(label() + "." + pick(allow))
		case n < 58:
			emit(pick(regex))
		case n < 68:
			emit(pick(modifier))
		case n < 74:
			emit(pick(wildcard))
		case n < 82:
			emit(pick(host))
		case n < 92:
			emit(label() + "." + label() + "." + []string{"com", "net", "org", "io", "xyz"}[rng.Intn(5)])
		case n < 96:
			emit(fmt.Sprintf("%d.%d.%d.%d", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)))
		default:
			emit(fmt.Sprintf("2001:db8:%x::%x", rng.Intn(65536), rng.Intn(65536)))
		}
	}

	sort.Strings(out)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for _, q := range out {
		fmt.Fprintln(w, q)
	}
}

// nameFromRule turns a rule text into a plausible host name: modifiers,
// anchors and separators are stripped.
func nameFromRule(text string) string {
	text = strings.TrimPrefix(text, "@@")
	if i := strings.LastIndex(text, "$"); i >= 0 {
		text = text[:i]
	}

	text = strings.TrimPrefix(text, "||")
	text = strings.TrimPrefix(text, "|")
	text = strings.TrimSuffix(text, "^")
	text = strings.TrimSuffix(text, "|")
	text = strings.TrimPrefix(text, "http://")
	text = strings.TrimPrefix(text, "https://")
	if i := strings.IndexAny(text, "/^"); i >= 0 {
		text = text[:i]
	}

	return strings.ToLower(text)
}

// nameFromRegex builds one string the regular expression of a "/.../" rule
// matches, by walking the parsed syntax tree.
func nameFromRegex(text string) string {
	if i := strings.LastIndex(text, "$"); i >= 0 && strings.HasSuffix(text[:i], "/") {
		text = text[:i]
	}

	if len(text) < 3 || text[0] != '/' || text[len(text)-1] != '/' {
		return ""
	}

	re, err := syntax.Parse(text[1:len(text)-1], syntax.Perl)
	if err != nil {
		return ""
	}

	var b strings.Builder
	var walk func(*syntax.Regexp)
	walk = func(n *syntax.Regexp) {
		switch n.Op {
		case syntax.OpLiteral:
			b.WriteString(string(n.Rune))
		case syntax.OpCharClass:
			if len(n.Rune) > 0 {
				b.WriteRune(n.Rune[0])
			}
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			b.WriteString("a")
		case syntax.OpConcat:
			for _, s := range n.Sub {
				walk(s)
			}
		case syntax.OpAlternate:
			walk(n.Sub[0])
		case syntax.OpCapture:
			walk(n.Sub[0])
		case syntax.OpPlus:
			walk(n.Sub[0])
		case syntax.OpRepeat:
			for i := 0; i < n.Min; i++ {
				walk(n.Sub[0])
			}
		}
	}
	walk(re)

	return strings.ToLower(b.String())
}
