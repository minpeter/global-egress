package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validProviderTOML(catalogPath string) string {
	return "[[providers]]\nid = \"mullvad\"\ntype = \"mullvad\"\nenabled = true\n\n[providers.catalog]\npath = \"" + catalogPath + "\"\n\n[providers.relays]\nurl = \"https://api.mullvad.net/www/relays/wireguard/\"\ncache = \"relays.json\"\nrefresh = \"24h\"\n\n[providers.entries]\nauto = 2\n"
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := write(t, dir, "config.toml", validProviderTOML("wireguard")+"\n[listen]\nsocks5 = \"10.0.0.70:1080\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := filepath.Join(dir, "wireguard"); cfg.Catalog.Path != want {
		t.Errorf("Catalog.Path = %q, want %q", cfg.Catalog.Path, want)
	}
	if cfg.Pool.SessionTTL != 10*time.Minute || cfg.Pool.MaxBatchTTL != 15*time.Minute || cfg.Pool.MaxSessionTTL != 24*time.Hour {
		t.Errorf("pool defaults were not preserved: %+v", cfg.Pool)
	}
	if cfg.Pool.MaxActive != 25 || cfg.Listen.HTTP != "127.0.0.1:3128" {
		t.Errorf("safety/listener defaults were not preserved")
	}
	if got := cfg.InventoryPath(); !strings.HasSuffix(got, "inventory.json") {
		t.Errorf("InventoryPath = %q", got)
	}
}

func TestPartialPoolConfigKeepsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "config.toml", validProviderTOML("/var/lib/global-egress/wireguard")+"\n[pool]\nmax_active = 25\npreopen = 3\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Pool.MaxConnsPerExit != 8 || cfg.Pool.MaxConcurrentConns != 256 {
		t.Errorf("pool defaults changed: %+v", cfg.Pool)
	}
}

func TestLoadReadsSecretFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "pw", "  hunter2\n")
	write(t, dir, "token", "tok3n\n")
	path := write(t, dir, "config.toml", validProviderTOML("/var/lib/global-egress/wireguard")+"\n[access]\npassword_file = \"pw\"\ncontrol_token_file = \"token\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Access.Password != "hunter2" || cfg.Access.ControlToken != "tok3n" {
		t.Errorf("secret files were not trimmed")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "config.toml", validProviderTOML("x")+"\npoool.max_active = 5\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("expected missing-file error")
	}
}

func TestValidate(t *testing.T) {
	base := func() Config { return Default() }
	cases := map[string]func(*Config){
		"no providers":             func(c *Config) { c.providers = nil },
		"no listeners":             func(c *Config) { c.Listen.SOCKS5 = ""; c.Listen.HTTP = "" },
		"bad client cidr":          func(c *Config) { c.Access.AllowedClients = []string{"nope"} },
		"bad denied cidr":          func(c *Config) { c.Destinations.DeniedCIDRs = []string{"nope"} },
		"auth without password":    func(c *Config) { c.Access.RequireAuth = true; c.Access.Password = "  " },
		"negative max_active":      func(c *Config) { c.Pool.MaxActive = -1 },
		"zero unique batch limit":  func(c *Config) { c.Pool.MaxUniqueBatches = 0 },
		"zero session limit":       func(c *Config) { c.Pool.MaxSessions = 0 },
		"batch ttl over maximum":   func(c *Config) { c.Pool.MaxBatchTTL = c.Pool.BatchTTL - time.Second },
		"session ttl over maximum": func(c *Config) { c.Pool.MaxSessionTTL = c.Pool.SessionTTL - time.Second },
		"preopen over budget":      func(c *Config) { c.Pool.MaxActive = 2; c.Pool.Preopen = 3 },
		"bad log level":            func(c *Config) { c.Log.Level = "loud" },
		"bad log format":           func(c *Config) { c.Log.Format = "yaml" },
		"invalid allowed port":     func(c *Config) { c.Destinations.AllowedPorts = []int{0} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAllowedClientPrefixes(t *testing.T) {
	cfg := Default()
	cfg.Access.AllowedClients = []string{"10.0.0.0/24", " ::1/128 "}
	prefixes, err := cfg.AllowedClientPrefixes()
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("prefixes = %v, err = %v", prefixes, err)
	}
}
