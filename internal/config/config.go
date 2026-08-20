// Package config loads and validates the service configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/minpeter/global-egress/internal/netguard"
)

// Mode selects where exit addresses come from.
type Mode string

const (
	// ModeWireGuard gives every slot its own tunnel. Simple and self-contained,
	// but each slot costs a provider key association, which is rate-limited.
	ModeWireGuard Mode = "wireguard"
	// ModeRelaySocks keeps a few entry tunnels up and exits through the SOCKS
	// proxy on each provider relay. Many more addresses, near-instant rotation,
	// and almost no key associations.
	ModeRelaySocks Mode = "relay-socks"
)

// Config is the on-disk configuration.
type Config struct {
	Mode      Mode          `toml:"mode"`
	Relays    RelayConfig   `toml:"-" json:"-"`
	Entries   EntryConfig   `toml:"-" json:"-"`
	Catalog   CatalogConfig `toml:"-" json:"-"`
	providers []Provider    `toml:"-" json:"-"`
	Listen    ListenConfig  `toml:"listen"`
	// Access controls who may use the proxy.
	Access AccessConfig `toml:"access"`
	// Pool tunes slot selection and lifecycle.
	Pool PoolConfig `toml:"pool"`
	// Destinations restricts where traffic may go.
	Destinations DestinationConfig `toml:"destinations"`
	// StateDir holds the measured-IP inventory.
	StateDir string `toml:"state_dir"`
	// Log configures logging.
	Log LogConfig `toml:"log"`
}

// RelayConfig locates the provider relay list.
type RelayConfig struct {
	// URL is the relay list endpoint.
	URL string `toml:"url"`
	// Cache is where the list is stored; relative paths resolve under state_dir.
	Cache string `toml:"cache"`
	// Refresh is how long a cached list is trusted before refetching.
	Refresh time.Duration `toml:"refresh"`
}

// EntryConfig selects the entry tunnels for relay-socks mode.
type EntryConfig struct {
	// Slots names catalog slots to use as entries, e.g. ["jp-tyo-wg-001"].
	// Prefer listing these explicitly: the best entry depends on where this
	// service runs, which cannot be derived from the catalog.
	Slots []string `toml:"slots"`
	// Auto picks this many entries spread across regions when Slots is empty.
	Auto int `toml:"auto"`
}

// CatalogConfig locates the WireGuard configuration bundle.
type CatalogConfig struct {
	Path string `toml:"path"`
}

// ListenConfig holds listener addresses. An empty value disables that listener.
type ListenConfig struct {
	SOCKS5  string `toml:"socks5"`
	HTTP    string `toml:"http"`
	Control string `toml:"control"`
}

// AccessConfig controls authentication and the client ACL.
type AccessConfig struct {
	// AllowedClients are CIDRs permitted to use the proxy and control API.
	AllowedClients []string `toml:"allowed_clients"`
	// Password, when set, is required from proxy clients. The username always
	// carries the selection policy, never an identity.
	Password string `toml:"password"`
	// PasswordFile reads the password from a file instead of the config.
	PasswordFile string `toml:"password_file"`
	// RequireAuth rejects proxy clients that present no credentials.
	RequireAuth bool `toml:"require_auth"`
	// RequirePolicy rejects proxy requests that carry no selection directives.
	// Useful when every caller is expected to choose a country or a session, and
	// an unnoticed fallback to an arbitrary exit would be a bug rather than a
	// convenience.
	RequirePolicy bool `toml:"require_policy"`
	// ControlToken, when set, is required as a Bearer token on the control API.
	ControlToken string `toml:"control_token"`
	// ControlTokenFile reads the control token from a file.
	ControlTokenFile string `toml:"control_token_file"`
}

// PoolConfig tunes the pool.
type PoolConfig struct {
	// MaxActive caps simultaneously open tunnels. Zero means "no limit", which
	// is only advisable after measuring memory use per slot.
	MaxActive int `toml:"max_active"`
	// Preopen brings this many tunnels up at startup so the first requests do
	// not pay for a handshake.
	Preopen int `toml:"preopen"`
	// MaxConnsPerExit caps concurrent connections through one exit, so load is
	// spread over relays instead of concentrated on one. Zero disables it.
	MaxConnsPerExit int `toml:"max_conns_per_exit"`
	// MaxConcurrentConns caps concurrent connections across the pool. Zero
	// disables it.
	MaxConcurrentConns int `toml:"max_concurrent_conns"`
	// SessionTTL is the default sticky-session lifetime.
	SessionTTL time.Duration `toml:"session_ttl"`
	// MaxSessionTTL caps a client-selected sticky-session lifetime.
	MaxSessionTTL time.Duration `toml:"max_session_ttl"`
	// MaxSessions caps concurrently retained sticky-session names.
	MaxSessions int `toml:"max_sessions"`
	// BatchTTL is how long a unique-IP batch is remembered.
	BatchTTL time.Duration `toml:"batch_ttl"`
	// MaxBatchTTL caps a client-selected unique-batch lifetime.
	MaxBatchTTL time.Duration `toml:"max_batch_ttl"`
	// MaxUniqueBatches caps concurrently active unique-IP batches.
	MaxUniqueBatches int `toml:"max_unique_batches"`
	// Cooldown is the default per-target cooldown applied by a report.
	Cooldown time.Duration `toml:"cooldown"`
	// PreferredTTL is how long a destination remembers a last-good slot.
	PreferredTTL time.Duration `toml:"preferred_ttl"`
	// PreferredMax is how many last-good slots a destination keeps.
	PreferredMax int `toml:"preferred_max"`
	// IdleTimeout closes tunnels unused for this long.
	IdleTimeout time.Duration `toml:"idle_timeout"`
	// HandshakeTimeout bounds bringing a tunnel up.
	HandshakeTimeout time.Duration `toml:"handshake_timeout"`
	// DialAttempts is how many slots a request tries before failing.
	DialAttempts int `toml:"dial_attempts"`
	// FailureBackoff is the base backoff for a failing slot.
	FailureBackoff time.Duration `toml:"failure_backoff"`
	// NewTunnelsPerWindow caps how many tunnels may be opened per
	// NewTunnelWindow. Providers restrict how fast one key may associate with
	// new relays, so this protects the key from being blocked. Zero disables it.
	NewTunnelsPerWindow int `toml:"new_tunnels_per_window"`
	// NewTunnelWindow is the period NewTunnelsPerWindow applies to.
	NewTunnelWindow time.Duration `toml:"new_tunnel_window"`
	// EntryExploreRate is the share of requests that deliberately use the
	// second-best entry, so alternatives keep being measured. Zero uses the
	// built-in default.
	EntryExploreRate float64 `toml:"entry_explore_rate"`
	// StableEntryRouting always uses the best known entry, trading self-correcting
	// routing for predictability.
	StableEntryRouting bool `toml:"stable_entry_routing"`
	// DialTimeout bounds connecting to the destination through a tunnel.
	DialTimeout time.Duration `toml:"dial_timeout"`
	// RelayIdleTimeout closes relayed connections after inactivity.
	RelayIdleTimeout time.Duration `toml:"relay_idle_timeout"`
	// IPCheckURL is the echo endpoint used to learn a slot's public IP.
	// Setting it to "" disables IP measurement, and with it unique-IP batches.
	IPCheckURL string `toml:"ip_check_url"`
	// IPCheckTimeout bounds one measurement.
	IPCheckTimeout time.Duration `toml:"ip_check_timeout"`
	// IPRefreshInterval is how long a measured IP is trusted.
	IPRefreshInterval time.Duration `toml:"ip_refresh_interval"`
	// IPCheckConcurrency caps simultaneous measurements.
	IPCheckConcurrency int `toml:"ip_check_concurrency"`
}

// DestinationConfig restricts destinations.
type DestinationConfig struct {
	// DeniedCIDRs replaces the built-in private-range denylist when non-nil.
	DeniedCIDRs []string `toml:"denied_cidrs"`
	// AllowedPorts, when non-empty, is an allowlist of destination ports.
	AllowedPorts []int `toml:"allowed_ports"`
}

// LogConfig configures logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `toml:"level"`
	// Format is "text" or "json".
	Format string `toml:"format"`
}

// Default returns a configuration with every optional value populated.
func Default() Config {
	return Config{
		Mode:      ModeRelaySocks,
		providers: []Provider{{providerType: ProviderMullvad, enabled: true, id: "mullvad"}},
		Relays: RelayConfig{
			URL:     "https://api.mullvad.net/www/relays/wireguard/",
			Cache:   "relays.json",
			Refresh: 24 * time.Hour,
		},
		Entries: EntryConfig{Auto: 2},
		Listen: ListenConfig{
			SOCKS5:  "127.0.0.1:1080",
			HTTP:    "127.0.0.1:3128",
			Control: "127.0.0.1:8080",
		},
		Access: AccessConfig{
			AllowedClients: []string{"127.0.0.1/32", "::1/128"},
		},
		Pool: PoolConfig{
			MaxActive:           25,
			MaxConnsPerExit:     8,
			MaxConcurrentConns:  256,
			Preopen:             0,
			SessionTTL:          10 * time.Minute,
			MaxSessionTTL:       24 * time.Hour,
			MaxSessions:         10_000,
			BatchTTL:            15 * time.Minute,
			MaxBatchTTL:         15 * time.Minute,
			MaxUniqueBatches:    10_000,
			Cooldown:            15 * time.Minute,
			PreferredTTL:        30 * time.Minute,
			PreferredMax:        8,
			IdleTimeout:         10 * time.Minute,
			HandshakeTimeout:    12 * time.Second,
			DialAttempts:        3,
			FailureBackoff:      30 * time.Second,
			NewTunnelsPerWindow: 120,
			NewTunnelWindow:     10 * time.Minute,
			DialTimeout:         30 * time.Second,
			RelayIdleTimeout:    5 * time.Minute,
			IPCheckURL:          "https://am.i.mullvad.net/ip",
			IPCheckTimeout:      15 * time.Second,
			IPRefreshInterval:   6 * time.Hour,
			IPCheckConcurrency:  4,
		},
		StateDir: "/var/lib/global-egress",
		Log:      LogConfig{Level: "info", Format: "text"},
	}
}

type rawConfig struct {
	Mode         Mode              `toml:"mode"`
	Listen       ListenConfig      `toml:"listen"`
	Access       AccessConfig      `toml:"access"`
	Pool         PoolConfig        `toml:"pool"`
	Destinations DestinationConfig `toml:"destinations"`
	StateDir     string            `toml:"state_dir"`
	Log          LogConfig         `toml:"log"`
	Providers    []rawProvider     `toml:"providers"`
}

// Load reads the sole supported TOML configuration format.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	input := rawConfig{
		Mode: cfg.Mode, Listen: cfg.Listen, Access: cfg.Access, Pool: cfg.Pool,
		Destinations: cfg.Destinations, StateDir: cfg.StateDir, Log: cfg.Log,
	}
	metadata, err := toml.Decode(string(raw), &input)
	if err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
		return Config{}, fmt.Errorf("config: unknown field %q", undecoded[0])
	}
	cfg.Mode, cfg.Listen, cfg.Access, cfg.Pool = input.Mode, input.Listen, input.Access, input.Pool
	cfg.Destinations, cfg.StateDir, cfg.Log = input.Destinations, input.StateDir, input.Log
	providers, err := normalizeProviders(input.Providers)
	if err != nil {
		return Config{}, err
	}
	cfg.providers = providers
	for _, provider := range providers {
		if provider.Type() == ProviderMullvad {
			mullvad, ok := provider.Mullvad()
			if ok {
				cfg.Catalog, cfg.Relays, cfg.Entries = mullvad.Catalog, mullvad.Relays, mullvad.Entries
			}
			break
		}
	}
	if err := cfg.finalize(filepath.Dir(path)); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// finalize resolves file references and validates the result.
func (c *Config) finalize(baseDir string) error {
	if c.Access.PasswordFile != "" {
		value, err := readSecret(resolvePath(baseDir, c.Access.PasswordFile))
		if err != nil {
			return err
		}
		c.Access.Password = value
	}
	if c.Access.ControlTokenFile != "" {
		value, err := readSecret(resolvePath(baseDir, c.Access.ControlTokenFile))
		if err != nil {
			return err
		}
		c.Access.ControlToken = value
	}
	if c.Catalog.Path != "" {
		c.Catalog.Path = resolvePath(baseDir, c.Catalog.Path)
	}
	if c.StateDir != "" {
		c.StateDir = resolvePath(baseDir, c.StateDir)
	}
	return c.Validate()
}

// Providers returns the validated providers from the TOML document.
func (c Config) Providers() []Provider {
	return append([]Provider(nil), c.providers...)
}

func (c Config) mullvadEnabled() bool {
	for _, provider := range c.providers {
		if provider.enabled && provider.providerType == ProviderMullvad {
			return true
		}
	}
	return false
}

// Validate checks the configuration for obvious mistakes.
func (c *Config) Validate() error {
	if len(c.providers) == 0 {
		return errors.New("config: providers must contain at least one provider")
	}
	switch c.Mode {
	case ModeWireGuard, ModeRelaySocks:
	default:
		return fmt.Errorf("config: mode %q is not %q or %q", c.Mode, ModeWireGuard, ModeRelaySocks)
	}
	if c.Mode == ModeRelaySocks {
		if c.mullvadEnabled() && len(c.Entries.Slots) == 0 && c.Entries.Auto <= 0 {
			return fmt.Errorf("config: relay-socks mode needs entries.slots or entries.auto")
		}
		if c.Relays.Refresh < 0 {
			return fmt.Errorf("config: relays.refresh must not be negative")
		}
	}
	if c.Listen.SOCKS5 == "" && c.Listen.HTTP == "" {
		return fmt.Errorf("config: at least one of listen.socks5 or listen.http must be set")
	}
	if _, err := c.AllowedClientPrefixes(); err != nil {
		return err
	}
	if c.Access.RequireAuth && strings.TrimSpace(c.Access.Password) == "" {
		return fmt.Errorf("config: access.require_auth needs a non-empty password")
	}
	if _, err := netguard.New(c.Destinations.DeniedCIDRs, c.Destinations.AllowedPorts); err != nil {
		return err
	}
	if c.Pool.MaxActive < 0 {
		return fmt.Errorf("config: pool.max_active must not be negative")
	}
	if c.Pool.Preopen < 0 {
		return fmt.Errorf("config: pool.preopen must not be negative")
	}
	if c.Pool.MaxConnsPerExit < 0 {
		return fmt.Errorf("config: pool.max_conns_per_exit must not be negative")
	}
	if c.Pool.MaxConcurrentConns < 0 {
		return fmt.Errorf("config: pool.max_concurrent_conns must not be negative")
	}
	if c.Pool.MaxUniqueBatches <= 0 {
		return fmt.Errorf("config: pool.max_unique_batches must be positive")
	}
	if c.Pool.MaxSessions <= 0 {
		return fmt.Errorf("config: pool.max_sessions must be positive")
	}
	if c.Pool.SessionTTL <= 0 {
		return fmt.Errorf("config: pool.session_ttl must be positive")
	}
	if c.Pool.MaxSessionTTL < c.Pool.SessionTTL {
		return fmt.Errorf("config: pool.max_session_ttl must be at least pool.session_ttl")
	}
	if c.Pool.BatchTTL <= 0 {
		return fmt.Errorf("config: pool.batch_ttl must be positive")
	}
	if c.Pool.MaxBatchTTL < c.Pool.BatchTTL {
		return fmt.Errorf("config: pool.max_batch_ttl must be at least pool.batch_ttl")
	}
	if c.Pool.EntryExploreRate < 0 || c.Pool.EntryExploreRate >= 1 {
		return fmt.Errorf("config: pool.entry_explore_rate must be in [0, 1)")
	}
	if c.Pool.NewTunnelsPerWindow < 0 {
		return fmt.Errorf("config: pool.new_tunnels_per_window must not be negative")
	}
	if c.Pool.NewTunnelWindow < 0 {
		return fmt.Errorf("config: pool.new_tunnel_window must not be negative")
	}
	if c.Pool.MaxActive > 0 && c.Pool.Preopen > c.Pool.MaxActive {
		return fmt.Errorf("config: pool.preopen (%d) exceeds pool.max_active (%d)",
			c.Pool.Preopen, c.Pool.MaxActive)
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level %q is not one of debug, info, warn, error", c.Log.Level)
	}
	switch strings.ToLower(c.Log.Format) {
	case "text", "json":
	default:
		return fmt.Errorf("config: log.format %q is not text or json", c.Log.Format)
	}
	return nil
}

// AllowedClientPrefixes parses the client ACL.
func (c *Config) AllowedClientPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range c.Access.AllowedClients {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("config: invalid access.allowed_clients entry %q: %w", raw, err)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// RelayCachePath resolves the relay list cache location.
func (c *Config) RelayCachePath() string {
	if c.Relays.Cache == "" {
		return ""
	}
	if filepath.IsAbs(c.Relays.Cache) {
		return c.Relays.Cache
	}
	if c.StateDir == "" {
		return c.Relays.Cache
	}
	return filepath.Join(c.StateDir, c.Relays.Cache)
}

// InventoryPath is where measured public IPs are persisted.
func (c *Config) InventoryPath() string {
	if c.StateDir == "" {
		return ""
	}
	return filepath.Join(c.StateDir, "inventory.json")
}

func resolvePath(baseDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func readSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("config: read secret %s: %w", path, err)
	}
	return strings.TrimSpace(string(raw)), nil
}
