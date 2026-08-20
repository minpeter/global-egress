package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTOMLProviderCentricConfigParsesOwnedProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `mode = "relay-socks"
state_dir = "/var/lib/global-egress"

[[providers]]
id = "mullvad-main"
type = "mullvad"
enabled = true

[providers.catalog]
path = "wireguard"

[providers.relays]
url = "https://api.mullvad.net/www/relays/wireguard/"
cache = "relays.json"
refresh = "24h"

[providers.entries]
auto = 2

[[providers]]
id = "direct-test"
type = "socks5"
enabled = true

[providers.socks5]
url = "socks5h://dummy-user:dummy-pass@proxy.example:1080"
country = "us"
city = "us-nyc"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	providers := cfg.Providers()
	if len(providers) != 2 || providers[0].ID() != "mullvad-main" || providers[1].ID() != "direct-test" {
		t.Fatalf("providers = %+v", providers)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "dummy-pass") {
		t.Fatal("config JSON leaked provider credential")
	}
}

func TestLoadRejectsLegacyYAMLAndSplitProviderConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("catalog:\n  path: wireguard\nproviders_file: providers.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted legacy YAML configuration")
	}
}

func TestLoadRejectsInvalidProviderSchemas(t *testing.T) {
	cases := map[string]string{
		"missing enabled": "[[providers]]\nid = \"m\"\ntype = \"socks5\"\n[providers.socks5]\nurl = \"socks5h://u:p@proxy.example:1080\"\n",
		"unknown field":   "[[providers]]\nid = \"m\"\ntype = \"socks5\"\nenabled = true\nextra = true\n[providers.socks5]\nurl = \"socks5h://u:p@proxy.example:1080\"\n",
		"bad credentials": "[[providers]]\nid = \"m\"\ntype = \"socks5\"\nenabled = true\n[providers.socks5]\nurl = \"socks5h://proxy.example:1080\"\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load accepted invalid provider schema")
			}
		})
	}
}
