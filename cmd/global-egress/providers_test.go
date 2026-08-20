package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/config"
)

func TestBuildSlotsAddsDirectProviderWithoutRelayEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `mode = "relay-socks"
[[providers]]
id = "external-test"
type = "socks5"
enabled = true
[providers.socks5]
url = "socks5h://dummy-user:dummy-pass@proxy.example:1080"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	specs, entries, err := buildSlots(t.Context(), cfg, &catalog.Bundle{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("buildSlots: %v", err)
	}
	if len(entries) != 0 || len(specs) != 1 {
		t.Fatalf("buildSlots returned %d specs and %d entries", len(specs), len(entries))
	}
	if specs[0].Provider != "external-test" || specs[0].Kind.String() != "direct-socks" {
		t.Fatalf("spec = %+v", specs[0])
	}
}

func TestMullvadRefreshConfigurationIsProviderScoped(t *testing.T) {
	cfg := config.Default()
	if !mullvadConfigured(cfg) {
		t.Fatal("default config should configure Mullvad")
	}
}
