// Package policy parses the egress selection policy that clients express
// through the proxy username.
//
// Encoding the policy in the username is the trick commercial proxy providers
// use, and it works with virtually every HTTP/SOCKS client without special
// support:
//
//	http://cc=jp;sess=job-1;ttl=600:<password>@egress.example:3128
//	socks5://uniq=batch-7:<password>@egress.example:1080
//
// Recognised directives:
//
//	any=1         no location constraint, chosen deliberately
//	cc=jp|us      restrict to these country codes
//	city=us-lax   restrict to these city labels
//	slot=id       pin one specific slot (mainly for debugging)
//	sess=name     sticky: reuse the same slot for this session
//	ttl=600       session lifetime in seconds (or Go duration, e.g. "10m")
//	uniq=batch    never reuse a public IP within this batch
//	health=scope  select using destination/model-specific exit health
//	not=1.2.3.4   exclude these public IPs
//
// Multiple values for cc, city and not are separated by "|". Directives are
// separated by ";" or ",". An empty username means "no constraints".
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Policy is a parsed client selection request.
type Policy struct {
	// AnyExit records that the client explicitly asked for no location
	// constraint.
	//
	// It exists to separate intent from accident. An empty policy can mean either
	// "anywhere is fine" or "my directives never arrived", and those deserve
	// different treatment when the operator has made a policy mandatory. Saying
	// any=1 is how a caller opts into the first meaning.
	AnyExit bool
	// Countries restricts selection to these ISO-3166-1 alpha-2 codes.
	Countries []string
	// Cities restricts selection to these "<country>-<city>" labels.
	Cities []string
	// Slot pins selection to one slot ID.
	Slot string
	// Session, when set, makes selection sticky under that name.
	Session string
	// TTL overrides the configured session lifetime. Zero means "use the default".
	TTL time.Duration
	// UniqueBatch, when set, forbids reusing a public IP already handed out
	// within that batch.
	UniqueBatch string
	// BatchTTL overrides the configured unique-batch lifetime. Zero uses the
	// server default.
	BatchTTL time.Duration
	// HealthScope selects the destination/model-specific health history used
	// for this request. It is an opaque, non-secret token shared with feedback.
	HealthScope string
	// ExcludeIPs lists public IPs the client refuses.
	ExcludeIPs []netip.Addr
}

// IsZero reports whether the client expressed nothing at all. An explicit any=1 is
// an expression, so it is not zero.
func (p Policy) IsZero() bool {
	return !p.AnyExit && len(p.Countries) == 0 && len(p.Cities) == 0 && p.Slot == "" &&
		p.Session == "" && p.TTL == 0 && p.UniqueBatch == "" && p.BatchTTL == 0 &&
		p.HealthScope == "" && len(p.ExcludeIPs) == 0
}

// String renders the policy in the same syntax it is parsed from. It never
// contains the password, but callers logging it should use LogString so excluded
// IP addresses stay out of operational logs.
func (p Policy) String() string {
	var parts []string
	if p.AnyExit {
		// Rendered with its value so the output stays parseable: every directive in
		// this grammar is key=value, and String is documented to round-trip.
		parts = append(parts, "any=1")
	}
	if len(p.Countries) > 0 {
		parts = append(parts, "cc="+strings.Join(p.Countries, "|"))
	}
	if len(p.Cities) > 0 {
		parts = append(parts, "city="+strings.Join(p.Cities, "|"))
	}
	if p.Slot != "" {
		parts = append(parts, "slot="+p.Slot)
	}
	if p.Session != "" {
		parts = append(parts, "sess="+p.Session)
	}
	if p.TTL > 0 {
		parts = append(parts, "ttl="+p.TTL.String())
	}
	if p.UniqueBatch != "" {
		parts = append(parts, "uniq="+p.UniqueBatch)
	}
	if p.BatchTTL > 0 {
		parts = append(parts, "bttl="+p.BatchTTL.String())
	}
	if p.HealthScope != "" {
		parts = append(parts, "health="+p.HealthScope)
	}
	for _, ip := range p.ExcludeIPs {
		parts = append(parts, "not="+ip.String())
	}
	if len(parts) == 0 {
		// Distinct from "any": nothing was supplied, rather than "anywhere" being
		// asked for. The two look the same in behaviour and different in intent,
		// and a header or log line should say which happened.
		return "(none)"
	}
	return strings.Join(parts, ";")
}

// LogString renders a policy for operational logs without exposing excluded IP
// addresses. It retains their count, which is enough to diagnose policy shape.
func (p Policy) LogString() string {
	excluded := len(p.ExcludeIPs)
	hasHealthScope := p.HealthScope != ""
	p.ExcludeIPs = nil
	p.HealthScope = ""
	rendered := p.String()
	var suffixes []string
	if hasHealthScope {
		suffixes = append(suffixes, "health=present")
	}
	if excluded > 0 {
		suffixes = append(suffixes, fmt.Sprintf("not_count=%d", excluded))
	}
	if len(suffixes) == 0 {
		return rendered
	}
	if rendered == "(none)" {
		return strings.Join(suffixes, ";")
	}
	return rendered + ";" + strings.Join(suffixes, ";")
}

// MaxUsernameLen bounds the username we are willing to parse.
const (
	MaxUsernameLen    = 512
	maxOpaqueTokenLen = 128
)

// Parse converts a proxy username into a Policy. An empty username yields an
// unconstrained policy. Unknown directives are rejected so that typos surface
// immediately instead of silently widening the selection.
func Parse(username string) (Policy, error) {
	var p Policy
	username = strings.TrimSpace(username)
	if username == "" {
		return p, nil
	}
	if len(username) > MaxUsernameLen {
		return p, fmt.Errorf("policy: username too long (%d > %d)", len(username), MaxUsernameLen)
	}

	// A username with no "=" is treated as an opaque account name rather than a
	// policy, so plain "user:pass" credentials keep working.
	if !strings.Contains(username, "=") {
		return p, nil
	}

	fields := strings.FieldsFunc(username, func(r rune) bool { return r == ';' || r == ',' })
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return Policy{}, fmt.Errorf("policy: directive %q is not key=value", field)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if value == "" {
			return Policy{}, fmt.Errorf("policy: directive %q has an empty value", key)
		}

		switch key {
		case "any":
			enabled, err := parseBool(value)
			if err != nil {
				return Policy{}, err
			}
			p.AnyExit = enabled
		case "cc", "country":
			p.Countries = appendLower(p.Countries, value)
		case "city":
			p.Cities = appendLower(p.Cities, value)
		case "slot":
			p.Slot = value
		case "sess", "session":
			p.Session = value
		case "ttl":
			ttl, err := parseTTL("ttl", value)
			if err != nil {
				return Policy{}, err
			}
			p.TTL = ttl
		case "uniq", "unique":
			p.UniqueBatch = value
		case "bttl":
			ttl, err := parseTTL("bttl", value)
			if err != nil {
				return Policy{}, err
			}
			if ttl == 0 {
				return Policy{}, fmt.Errorf("policy: bttl must be positive")
			}
			p.BatchTTL = ttl
		case "health":
			p.HealthScope = value
		case "not", "exclude":
			for _, item := range strings.Split(value, "|") {
				addr, err := netip.ParseAddr(strings.TrimSpace(item))
				if err != nil {
					return Policy{}, fmt.Errorf("policy: not=%q is not an IP address", item)
				}
				p.ExcludeIPs = append(p.ExcludeIPs, addr)
			}
		default:
			return Policy{}, fmt.Errorf("policy: unknown directive %q", key)
		}
	}

	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// parseBool accepts the spellings people actually type in a proxy username.
func parseBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y":
		return true, nil
	case "0", "false", "no", "n":
		return false, nil
	}
	return false, fmt.Errorf("policy: any=%q is not a boolean", value)
}

func (p *Policy) validate() error {
	for name, value := range map[string]string{
		"session":      p.Session,
		"slot":         p.Slot,
		"unique batch": p.UniqueBatch,
		"health scope": p.HealthScope,
	} {
		if value != "" && !isSafeOpaqueToken(value) {
			return fmt.Errorf("policy: %s contains unsafe characters", name)
		}
	}
	for _, cc := range p.Countries {
		if !isASCIICountryCode(cc) {
			return fmt.Errorf("policy: cc=%q is not a 2-letter country code", cc)
		}
	}
	for _, city := range p.Cities {
		if !isSafeOpaqueToken(city) {
			return fmt.Errorf("policy: city contains unsafe characters")
		}
		if !strings.Contains(city, "-") {
			return fmt.Errorf("policy: city=%q should look like \"us-lax\"", city)
		}
	}
	if p.TTL < 0 {
		return fmt.Errorf("policy: ttl must not be negative")
	}
	if p.BatchTTL < 0 {
		return fmt.Errorf("policy: bttl must not be negative")
	}
	if p.BatchTTL > 0 && p.UniqueBatch == "" {
		return fmt.Errorf("policy: bttl requires uniq")
	}
	// any= is about location, so it contradicts the directives that pin one, but
	// composes fine with session stickiness and unique batches.
	if p.AnyExit {
		var conflicts []string
		if len(p.Countries) > 0 {
			conflicts = append(conflicts, "cc")
		}
		if len(p.Cities) > 0 {
			conflicts = append(conflicts, "city")
		}
		if p.Slot != "" {
			conflicts = append(conflicts, "slot")
		}
		if len(conflicts) > 0 {
			return fmt.Errorf("policy: any= means no location constraint, so it cannot be "+
				"combined with %s", strings.Join(conflicts, ", "))
		}
	}
	sort.Strings(p.Countries)
	sort.Strings(p.Cities)
	return nil
}

func isSafeOpaqueToken(value string) bool {
	if len(value) > maxOpaqueTokenLen {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isASCIICountryCode(value string) bool {
	return len(value) == 2 &&
		value[0] >= 'a' && value[0] <= 'z' &&
		value[1] >= 'a' && value[1] <= 'z'
}

func appendLower(dst []string, value string) []string {
	for _, item := range strings.Split(value, "|") {
		if item = strings.ToLower(strings.TrimSpace(item)); item != "" {
			dst = append(dst, item)
		}
	}
	return dst
}

// parseTTL accepts bare seconds ("600") and Go durations ("10m").
func parseTTL(name, value string) (time.Duration, error) {
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0, fmt.Errorf("policy: %s=%q must not be negative", name, value)
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("policy: %s=%q is neither seconds nor a duration", name, value)
	}
	if d < 0 {
		return 0, fmt.Errorf("policy: %s=%q must not be negative", name, value)
	}
	return d, nil
}
