package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := write(t, dir, "config.yaml", `
catalog:
  path: wireguard
listen:
  socks5: 10.0.0.70:1080
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Relative paths resolve against the config file's directory.
	if want := filepath.Join(dir, "wireguard"); cfg.Catalog.Path != want {
		t.Errorf("Catalog.Path = %q, want %q", cfg.Catalog.Path, want)
	}
	if cfg.Pool.SessionTTL != 10*time.Minute {
		t.Errorf("SessionTTL = %s, want the 10m default", cfg.Pool.SessionTTL)
	}
	if cfg.Pool.MaxBatchTTL != 15*time.Minute {
		t.Errorf("MaxBatchTTL = %s, want the 15m default", cfg.Pool.MaxBatchTTL)
	}
	if cfg.Pool.MaxSessionTTL != 24*time.Hour {
		t.Errorf("MaxSessionTTL = %s, want the 24h default", cfg.Pool.MaxSessionTTL)
	}
	if cfg.Pool.MaxActive != 25 {
		t.Errorf("MaxActive = %d, want the default 25", cfg.Pool.MaxActive)
	}
	if cfg.Listen.HTTP != "127.0.0.1:3128" {
		t.Errorf("Listen.HTTP = %q, want the default", cfg.Listen.HTTP)
	}
	if got := cfg.InventoryPath(); !strings.HasSuffix(got, "inventory.json") {
		t.Errorf("InventoryPath = %q", got)
	}
}

// Defaults are easy to add a field for and forget to populate, and the symptom is
// silent: a limit meant to protect the provider simply never applies. Assert the
// safety-relevant ones explicitly.
func TestDefaultsPopulateSafetyLimits(t *testing.T) {
	t.Parallel()
	cfg := Default()

	cases := map[string]int{
		"pool.max_active":             cfg.Pool.MaxActive,
		"pool.max_conns_per_exit":     cfg.Pool.MaxConnsPerExit,
		"pool.max_concurrent_conns":   cfg.Pool.MaxConcurrentConns,
		"pool.new_tunnels_per_window": cfg.Pool.NewTunnelsPerWindow,
		"pool.dial_attempts":          cfg.Pool.DialAttempts,
		"pool.max_unique_batches":     cfg.Pool.MaxUniqueBatches,
		"pool.max_sessions":           cfg.Pool.MaxSessions,
		"pool.preferred_max":          cfg.Pool.PreferredMax,
	}
	for name, value := range cases {
		if value <= 0 {
			t.Errorf("%s defaults to %d; a zero here disables the protection", name, value)
		}
	}
	for name, value := range map[string]time.Duration{
		"pool.new_tunnel_window": cfg.Pool.NewTunnelWindow,
		"pool.cooldown":          cfg.Pool.Cooldown,
		"pool.preferred_ttl":     cfg.Pool.PreferredTTL,
		"pool.session_ttl":       cfg.Pool.SessionTTL,
		"pool.max_session_ttl":   cfg.Pool.MaxSessionTTL,
	} {
		if value <= 0 {
			t.Errorf("%s defaults to %s", name, value)
		}
	}
	if cfg.Pool.MaxUniqueBatches != 10_000 {
		t.Errorf("MaxUniqueBatches = %d, want 10000", cfg.Pool.MaxUniqueBatches)
	}
	if cfg.Mode != ModeRelaySocks {
		t.Errorf("Mode defaults to %q, want %q", cfg.Mode, ModeRelaySocks)
	}
}

func TestDeploymentExampleFailsClosed(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"../../deploy/config.example.yaml",
		"../../deploy/docker/config.example.yaml",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			blob, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read deployment example: %v", err)
			}
			var example struct {
				Access struct {
					PasswordFile  string `yaml:"password_file"`
					RequireAuth   bool   `yaml:"require_auth"`
					RequirePolicy bool   `yaml:"require_policy"`
				} `yaml:"access"`
			}
			if err := yaml.Unmarshal(blob, &example); err != nil {
				t.Fatalf("parse deployment example: %v", err)
			}
			if example.Access.PasswordFile == "" {
				t.Error("deployment example must configure password_file")
			}
			if !example.Access.RequireAuth {
				t.Error("deployment example must require proxy credentials")
			}
			if !example.Access.RequirePolicy {
				t.Error("deployment example must require an explicit egress policy")
			}
		})
	}
}

// A config that sets only a few pool fields must keep the rest of the defaults,
// which is what makes the limits apply without every deployment restating them.
func TestPartialPoolConfigKeepsDefaults(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := write(t, dir, "config.yaml", `
catalog:
  path: /var/lib/global-egress/wireguard
pool:
  max_active: 25
  preopen: 3
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Pool.MaxConnsPerExit != 8 {
		t.Errorf("MaxConnsPerExit = %d, want the default 8", cfg.Pool.MaxConnsPerExit)
	}
	if cfg.Pool.MaxConcurrentConns != 256 {
		t.Errorf("MaxConcurrentConns = %d, want the default 256", cfg.Pool.MaxConcurrentConns)
	}
}

func TestLoadReadsSecretFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write(t, dir, "pw", "  hunter2\n")
	write(t, dir, "token", "tok3n\n")
	path := write(t, dir, "config.yaml", `
catalog:
  path: /var/lib/global-egress/wireguard
access:
  password_file: pw
  control_token_file: token
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Access.Password != "hunter2" {
		t.Errorf("Password = %q, want the trimmed file content", cfg.Access.Password)
	}
	if cfg.Access.ControlToken != "tok3n" {
		t.Errorf("ControlToken = %q", cfg.Access.ControlToken)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := write(t, dir, "config.yaml", `
catalog:
  path: x
poool:
  max_active: 5
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown field (typos must not be silently ignored)")
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	base := func() Config {
		cfg := Default()
		cfg.Catalog.Path = "/tmp/wg"
		return cfg
	}

	cases := map[string]func(*Config){
		"no catalog":              func(c *Config) { c.Catalog.Path = "" },
		"no listeners":            func(c *Config) { c.Listen.SOCKS5 = ""; c.Listen.HTTP = "" },
		"bad client cidr":         func(c *Config) { c.Access.AllowedClients = []string{"nope"} },
		"bad denied cidr":         func(c *Config) { c.Destinations.DeniedCIDRs = []string{"nope"} },
		"auth without password":   func(c *Config) { c.Access.RequireAuth = true; c.Access.Password = "  " },
		"negative max_active":     func(c *Config) { c.Pool.MaxActive = -1 },
		"zero unique batch limit": func(c *Config) { c.Pool.MaxUniqueBatches = 0 },
		"zero session limit":      func(c *Config) { c.Pool.MaxSessions = 0 },
		"batch ttl over maximum":  func(c *Config) { c.Pool.MaxBatchTTL = c.Pool.BatchTTL - time.Second },
		"session ttl over maximum": func(c *Config) {
			c.Pool.MaxSessionTTL = c.Pool.SessionTTL - time.Second
		},
		"preopen over budget":  func(c *Config) { c.Pool.MaxActive = 2; c.Pool.Preopen = 3 },
		"bad log level":        func(c *Config) { c.Log.Level = "loud" },
		"bad log format":       func(c *Config) { c.Log.Format = "yaml" },
		"invalid allowed port": func(c *Config) { c.Destinations.AllowedPorts = []int{0} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		cfg := base()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})
}

func TestAllowedClientPrefixes(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.Access.AllowedClients = []string{"10.0.0.0/24", " ::1/128 "}
	prefixes, err := cfg.AllowedClientPrefixes()
	if err != nil {
		t.Fatalf("AllowedClientPrefixes: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("len = %d, want 2", len(prefixes))
	}
	if prefixes[0].String() != "10.0.0.0/24" {
		t.Errorf("prefix[0] = %s", prefixes[0])
	}
}

func TestInventoryPathWithoutStateDir(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.StateDir = ""
	if got := cfg.InventoryPath(); got != "" {
		t.Errorf("InventoryPath = %q, want empty when state_dir is unset", got)
	}
}
