package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseEmptyAndPlainUsername(t *testing.T) {
	t.Parallel()
	for _, username := range []string{"", "   ", "someaccount"} {
		pol, err := Parse(username)
		if err != nil {
			t.Fatalf("Parse(%q): %v", username, err)
		}
		if !pol.IsZero() {
			t.Errorf("Parse(%q) = %v, want an unconstrained policy", username, pol)
		}
	}
}

func TestParseDirectives(t *testing.T) {
	t.Parallel()
	pol, err := Parse(
		"cc=JP|us;city=us-lax;sess=job-1;ttl=600;uniq=batch-7;bttl=30s;" +
			"health=opencode-zen.deepseek-v4-flash-0731;not=1.2.3.4|5.6.7.8",
	)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(pol.Countries), 2; got != want {
		t.Fatalf("len(Countries) = %d, want %d", got, want)
	}
	// Values are lower-cased and sorted so that logging and comparison are stable.
	if pol.Countries[0] != "jp" || pol.Countries[1] != "us" {
		t.Errorf("Countries = %v, want [jp us]", pol.Countries)
	}
	if len(pol.Cities) != 1 || pol.Cities[0] != "us-lax" {
		t.Errorf("Cities = %v", pol.Cities)
	}
	if pol.Session != "job-1" {
		t.Errorf("Session = %q", pol.Session)
	}
	if pol.TTL != 10*time.Minute {
		t.Errorf("TTL = %s, want 10m", pol.TTL)
	}
	if pol.BatchTTL != 30*time.Second {
		t.Errorf("BatchTTL = %s, want 30s", pol.BatchTTL)
	}
	if pol.UniqueBatch != "batch-7" {
		t.Errorf("UniqueBatch = %q", pol.UniqueBatch)
	}
	if pol.HealthScope != "opencode-zen.deepseek-v4-flash-0731" {
		t.Errorf("HealthScope = %q", pol.HealthScope)
	}
	if len(pol.ExcludeIPs) != 2 {
		t.Errorf("ExcludeIPs = %v, want 2 entries", pol.ExcludeIPs)
	}
	if pol.IsZero() {
		t.Error("IsZero() = true for a populated policy")
	}
}

func TestParseBatchTTLRequiresUniqueBatch(t *testing.T) {
	t.Parallel()
	for _, input := range []string{"bttl=30s", "bttl=0", "uniq=batch;bttl=0"} {
		if _, err := Parse(input); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", input)
		}
	}
}

func TestParseTTLAcceptsDuration(t *testing.T) {
	t.Parallel()
	pol, err := Parse("ttl=90s")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.TTL != 90*time.Second {
		t.Errorf("TTL = %s, want 90s", pol.TTL)
	}
}

func TestParseCommaSeparator(t *testing.T) {
	t.Parallel()
	pol, err := Parse("cc=de,sess=x")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pol.Countries) != 1 || pol.Session != "x" {
		t.Errorf("unexpected policy %v", pol)
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown directive":    "contry=jp",
		"empty value":          "cc=",
		"bad country":          "cc=japan",
		"unsafe country":       "cc=\x00a",
		"bad city":             "city=lax",
		"unsafe city":          "city=us-lax\r\nX-Injected: yes",
		"not an ip":            "not=example.com",
		"negative ttl":         "ttl=-5",
		"unparsable ttl":       "ttl=soon",
		"missing key or value": "cc=jp;=x",
		"unsafe session":       "sess=job\r\nX-Injected: yes",
		"unsafe unique batch":  "uniq=batch\nx",
		"unsafe slot":          "slot=entry\rx",
	}
	for name, username := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(username); err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", username)
			}
		})
	}
}

func TestParseRejectsOverlongUsername(t *testing.T) {
	t.Parallel()
	long := make([]byte, MaxUsernameLen+1)
	for i := range long {
		long[i] = 'a'
	}
	// Include "=" so it is treated as a policy rather than an account name.
	if _, err := Parse("cc=" + string(long)); err == nil {
		t.Fatal("expected an error for an overlong username")
	}
}

func TestStringRoundTrips(t *testing.T) {
	t.Parallel()
	const input = "cc=jp;sess=job-1;ttl=10m;uniq=b1;not=1.2.3.4"
	pol, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reparsed, err := Parse(pol.String())
	if err != nil {
		t.Fatalf("Parse(String()): %v", err)
	}
	if reparsed.String() != pol.String() {
		t.Errorf("round trip changed the policy: %q -> %q", pol.String(), reparsed.String())
	}
}

func TestLogStringRedactsExcludedIPs(t *testing.T) {
	t.Parallel()
	pol, err := Parse(
		"cc=jp;health=opencode-zen.deepseek-v4-flash-0731;" +
			"not=203.0.113.4|198.51.100.8",
	)
	if err != nil {
		t.Fatal(err)
	}
	got := pol.LogString()
	if got != "cc=jp;health=present;not_count=2" {
		t.Errorf("LogString() = %q, want redacted health and IP count", got)
	}
	if strings.Contains(got, "deepseek") {
		t.Errorf("LogString() leaked the health scope: %q", got)
	}
	for _, ip := range []string{"203.0.113.4", "198.51.100.8"} {
		if strings.Contains(got, ip) {
			t.Errorf("LogString() leaked %q: %q", ip, got)
		}
	}
}

func TestStringDistinguishesNothingFromAnywhere(t *testing.T) {
	t.Parallel()
	// These behave identically and mean different things. A header or log line that
	// cannot tell them apart is how a dropped policy goes unnoticed.
	var nothing Policy
	if got := nothing.String(); got != "(none)" {
		t.Errorf("empty policy String() = %q, want (none)", got)
	}

	anywhere, err := Parse("any=1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := anywhere.String(); got != "any=1" {
		t.Errorf("any=1 String() = %q, want any=1", got)
	}
}

func TestAnyRoundTripsThroughString(t *testing.T) {
	t.Parallel()
	// String is documented to round-trip, and it is what the X-Egress-Policy header
	// carries, so a rendering the parser rejects would be a quiet inconsistency.
	original, err := Parse("any=1;sess=job-1;uniq=b1")
	if err != nil {
		t.Fatal(err)
	}
	rendered := original.String()
	reparsed, err := Parse(rendered)
	if err != nil {
		t.Fatalf("Parse(%q): %v", rendered, err)
	}
	if reparsed.String() != rendered {
		t.Errorf("round trip changed the policy: %q -> %q", rendered, reparsed.String())
	}
	if !reparsed.AnyExit {
		t.Error("AnyExit lost in the round trip")
	}
}

func TestAnyIsAnExpressedPolicy(t *testing.T) {
	t.Parallel()
	// The point of any=1: it places no constraint, yet counts as having said
	// something, so require_policy accepts it while still rejecting silence.
	var nothing Policy
	if !nothing.IsZero() {
		t.Error("an empty policy should be zero")
	}

	anywhere, err := Parse("any=1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if anywhere.IsZero() {
		t.Error("any=1 should not be zero: the client did express something")
	}
	if len(anywhere.Countries) != 0 || anywhere.Slot != "" {
		t.Error("any=1 must not add constraints")
	}
}

func TestAnyAcceptsCommonSpellings(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"1", "true", "yes", "y", "TRUE"} {
		pol, err := Parse("any=" + value)
		if err != nil {
			t.Errorf("any=%s: %v", value, err)
			continue
		}
		if !pol.AnyExit {
			t.Errorf("any=%s did not set AnyExit", value)
		}
	}
	for _, value := range []string{"0", "false", "no"} {
		pol, err := Parse("any=" + value)
		if err != nil {
			t.Errorf("any=%s: %v", value, err)
			continue
		}
		if pol.AnyExit {
			t.Errorf("any=%s set AnyExit", value)
		}
	}
	if _, err := Parse("any=maybe"); err == nil {
		t.Error("any=maybe should be rejected")
	}
}

func TestAnyComposesWithSessionButNotLocation(t *testing.T) {
	t.Parallel()
	// "anywhere, but keep me on it" is a real request.
	pol, err := Parse("any=1;sess=job-1;uniq=b1")
	if err != nil {
		t.Fatalf("any with session and batch: %v", err)
	}
	if !pol.AnyExit || pol.Session != "job-1" || pol.UniqueBatch != "b1" {
		t.Errorf("unexpected policy %v", pol)
	}

	// "anywhere in Japan" is not: it contradicts itself, and silently letting one
	// side win would be worse than saying so.
	for _, input := range []string{"any=1;cc=jp", "any=1;city=us-lax", "any=1;slot=x"} {
		if _, err := Parse(input); err == nil {
			t.Errorf("Parse(%q) succeeded, want a conflict error", input)
		}
	}
}
