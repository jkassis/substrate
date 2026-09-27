// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package egresspolicy evaluates an Actor's EgressPolicy against a
// destination. ateapi validates patterns and CIDRs with the same parsers the
// gateway matches with, so the two cannot drift.
//
// The package is pure: no I/O, no logging.
package egresspolicy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// Destination is what a request or connection is going to, as far as the leg
// evaluating it can tell. A request the gateway can read has the Hostname it
// named, when that is a DNS name, and the IP the actor dialed, when the leg
// knows it; a connection has only IP and Port. A rule that needs a field the
// leg cannot supply never matches there.
type Destination struct {
	// Hostname is the normalized DNS name: lowercase ASCII, no trailing dot.
	// Empty when the destination was not named by a hostname.
	Hostname string
	// IP is the address that will be dialed, when known. Zero when unknown.
	IP netip.Addr
	// Port is the destination port, when known. Zero when unknown.
	Port uint16
}

// Decision is the outcome of evaluating a policy against a Destination.
type Decision struct {
	// Allowed reports whether some rule authorized the destination.
	Allowed bool
	// RuleIndex is the index of the first matching rule in the policy, or -1
	// when nothing matched.
	RuleIndex int
	// Effects are the effects of the matching rule, when it is a hostname
	// rule that declares any. Nil otherwise.
	Effects *ateapipb.EgressRuleEffects
	// ByName reports that a hostname rule matched: the destination was
	// authorized on its name, so the name is what to dial.
	ByName bool
}

// Policy is an EgressPolicy with its patterns and CIDRs parsed once, ready
// to be evaluated many times.
type Policy struct {
	rules []compiledRule
}

type compiledRule struct {
	hostnames []HostnamePattern
	effects   *ateapipb.EgressRuleEffects
	cidrs     []netip.Prefix
	all       bool
	public    bool
	ports     map[uint16]struct{}
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func isPublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

// Compile parses every pattern and CIDR in policy. ateapi validates with the
// same parsers, so nothing should fail here; an entry that does (an older
// ateapi accepted it) is dropped and reported, which fails closed because it
// only narrows an allow rule. The Policy is always usable.
func Compile(policy *ateapipb.EgressPolicy) (*Policy, []error) {
	var errs []error
	compiled := &Policy{}
	for i, rule := range policy.GetRules() {
		cr := compiledRule{ports: make(map[uint16]struct{}, len(rule.GetPorts()))}
		for _, raw := range rule.GetPorts() {
			if raw < 1 || raw > 65535 {
				errs = append(errs, fmt.Errorf("rules[%d].ports: %d is not a valid destination port", i, raw))
				continue
			}
			cr.ports[uint16(raw)] = struct{}{}
		}
		switch {
		case rule.GetHostnames() != nil:
			for _, raw := range rule.GetHostnames().GetPatterns() {
				pattern, err := ParseHostnamePattern(raw)
				if err != nil {
					errs = append(errs, fmt.Errorf("rules[%d].hostnames: %w", i, err))
					continue
				}
				cr.hostnames = append(cr.hostnames, pattern)
			}
			cr.effects = rule.GetHostnames().GetEffects()
		case rule.GetCidrs() != nil:
			for _, raw := range rule.GetCidrs().GetCidrs() {
				cidr, err := ParseCIDR(raw)
				if err != nil {
					errs = append(errs, fmt.Errorf("rules[%d].cidrs: %w", i, err))
					continue
				}
				cr.cidrs = append(cr.cidrs, cidr)
			}
		case rule.GetAll() != nil:
			cr.all = true
		case rule.GetPublic() != nil:
			cr.public = true
		}
		compiled.rules = append(compiled.rules, cr)
	}
	return compiled, errs
}

// RuleCount is the number of rules in the policy, dropped entries included.
// A policy with no rules can authorize nothing.
func (p *Policy) RuleCount() int { return len(p.rules) }

// HasHostnameRules reports whether any rule can match a hostname. A decision
// point that sees only an address needs this before refusing a connection
// whose requests might still be allowed by name.
func (p *Policy) HasHostnameRules() bool {
	for _, rule := range p.rules {
		if len(rule.hostnames) > 0 {
			return true
		}
	}
	return false
}

// Evaluate walks the rules in order and returns the first that matches dest.
// Only that rule's effects apply; a request is denied when no rule matches.
func (p *Policy) Evaluate(dest Destination) Decision {
	for i, rule := range p.rules {
		if len(rule.ports) > 0 {
			if _, allowed := rule.ports[dest.Port]; !allowed {
				continue
			}
		}
		switch {
		case rule.all:
			return Decision{Allowed: true, RuleIndex: i}
		case rule.public:
			if isPublicAddress(dest.IP) {
				return Decision{Allowed: true, RuleIndex: i}
			}
		case len(rule.hostnames) > 0:
			if dest.Hostname == "" {
				continue
			}
			for _, pattern := range rule.hostnames {
				if pattern.Matches(dest.Hostname) {
					return Decision{Allowed: true, RuleIndex: i, Effects: rule.effects, ByName: true}
				}
			}
		case len(rule.cidrs) > 0:
			if !dest.IP.IsValid() {
				continue
			}
			ip := dest.IP.Unmap()
			for _, cidr := range rule.cidrs {
				if cidr.Contains(ip) {
					return Decision{Allowed: true, RuleIndex: i}
				}
			}
		}
	}
	return Decision{RuleIndex: -1}
}

// HostnamePattern is one parsed HostnameRule pattern: an exact name, or a
// wildcard standing in for the whole leftmost label.
type HostnamePattern struct {
	// name is the exact name, or the suffix after "*." for a wildcard.
	name     string
	wildcard bool
	// dotSuffix is "." + name, built once so Matches does not allocate per call.
	dotSuffix string
}

// ParseHostnamePattern parses a HostnameRule pattern. A pattern is a lowercase
// DNS-1123 subdomain, optionally prefixed with "*." to match exactly one
// non-empty leftmost label. IP literals, ports, URLs, trailing dots, and any
// other placement of "*" are rejected.
func ParseHostnamePattern(raw string) (HostnamePattern, error) {
	name, wildcard := strings.CutPrefix(raw, "*.")
	if !isHostname(name) {
		return HostnamePattern{}, fmt.Errorf("%q is not a valid hostname pattern", raw)
	}
	pattern := HostnamePattern{name: name, wildcard: wildcard}
	if wildcard {
		pattern.dotSuffix = "." + name
	}
	return pattern, nil
}

// String returns the pattern in the form it was written.
func (p HostnamePattern) String() string {
	if p.wildcard {
		return "*." + p.name
	}
	return p.name
}

// Matches reports whether hostname, already normalized as by
// NormalizeAuthority, matches the pattern. "*.example.com" matches
// "api.example.com" but neither "example.com" nor "a.b.example.com".
func (p HostnamePattern) Matches(hostname string) bool {
	if !p.wildcard {
		return hostname == p.name
	}
	label, found := strings.CutSuffix(hostname, p.dotSuffix)
	return found && label != "" && !strings.Contains(label, ".")
}

// ParseCIDR parses one CIDRRule entry. Only the canonical form is
// accepted: no leading zeros, no bits set beyond the prefix length, IPv6 in
// RFC 5952 lowercase compressed notation, and no IPv4-mapped IPv6 addresses.
func ParseCIDR(raw string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR", raw)
	}
	// Evaluate matches unmapped addresses, so a mapped CIDR could never match
	// anything; refuse it rather than accept a rule that silently does nothing.
	if cidr.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 CIDR", raw)
	}
	if cidr != cidr.Masked() || cidr.String() != raw {
		return netip.Prefix{}, fmt.Errorf("%q is not in canonical form (%s)", raw, cidr.Masked())
	}
	return cidr, nil
}

// NormalizeAuthority turns an :authority or Host value into a Destination:
// port split off, IP literal to IP, DNS name lowercased with one trailing dot
// removed and checked as a DNS-1123 subdomain. Anything else is an error, and
// the caller should deny.
func NormalizeAuthority(authority string) (Destination, error) {
	if authority == "" {
		return Destination{}, errors.New("authority is empty")
	}
	host := authority
	var port uint16
	if h, p, err := net.SplitHostPort(authority); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return Destination{}, fmt.Errorf("authority %q has an invalid port", authority)
		}
		host, port = h, uint16(n)
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return Destination{}, fmt.Errorf("authority %q has an IPv6 zone", authority)
		}
		return Destination{IP: addr.Unmap(), Port: port}, nil
	}

	name := lowerASCII(strings.TrimSuffix(host, "."))
	if !isHostname(name) {
		return Destination{}, fmt.Errorf("authority %q is neither a DNS hostname nor an IP literal", authority)
	}
	return Destination{Hostname: name, Port: port}, nil
}

// isHostname reports whether name is a lowercase DNS-1123 subdomain whose last
// label is not all digits. RFC 1123 section 2.1 requires that, and it is what
// keeps a dotted-decimal address from passing as a name, including spellings
// like "01.2.3.4" that netip rejects but resolvers accept. IPv6 literals fail
// the subdomain check on their own.
func isHostname(name string) bool {
	if len(content.IsDNS1123Subdomain(name)) != 0 {
		return false
	}
	return !allDigits(name[strings.LastIndexByte(name, '.')+1:])
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// lowerASCII folds A-Z only. strings.ToLower would also fold non-ASCII onto
// ASCII letters (U+212A KELVIN SIGN onto "k") and let a non-ASCII spelling
// match a pattern for a different name.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
