package policy

import "testing"

func TestParseProviderDirectiveRoundTrips(t *testing.T) {
	t.Parallel()
	pol, err := Parse("provider=external-test;sess=job-1")
	if err != nil {
		t.Fatalf("Parse provider directive: %v", err)
	}
	if got := pol.Provider; got != "external-test" {
		t.Fatalf("Provider = %q, want external-test", got)
	}
	if got := pol.String(); got != "provider=external-test;sess=job-1" {
		t.Fatalf("String() = %q, want provider selection to round-trip", got)
	}
}
