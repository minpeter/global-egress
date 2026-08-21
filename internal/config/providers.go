package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ProviderType identifies a configured provider variant.
type ProviderType string

const (
	ProviderMullvad ProviderType = "mullvad"
	ProviderSOCKS5  ProviderType = "socks5"
)

// MullvadConfig contains settings owned by one Mullvad provider.
type MullvadConfig struct {
	Catalog CatalogConfig
	Relays  RelayConfig
	Entries EntryConfig
}

type Provider struct {
	providerType ProviderType
	enabled      bool
	id           string
	country      string
	city         string
	sessions     int
	proxyURL     *url.URL
	mullvad      *MullvadConfig
}

func (p Provider) Type() ProviderType { return p.providerType }
func (p Provider) Enabled() bool      { return p.enabled }
func (p Provider) ID() string         { return p.id }
func (p Provider) Country() string    { return p.country }
func (p Provider) City() string       { return p.city }
func (p Provider) SOCKSURL() *url.URL { return p.proxyURL }

// SOCKSSessions returns the number of sticky logical sessions requested for a
// rotating SOCKS endpoint. Zero preserves one ordinary rotating slot.
func (p Provider) SOCKSSessions() int { return p.sessions }

func (p Provider) Mullvad() (MullvadConfig, bool) {
	if p.mullvad == nil {
		return MullvadConfig{}, false
	}
	return *p.mullvad, true
}

type rawProvider struct {
	Type    string         `toml:"type"`
	Enabled *bool          `toml:"enabled"`
	ID      string         `toml:"id"`
	Catalog *CatalogConfig `toml:"catalog"`
	Relays  *RelayConfig   `toml:"relays"`
	Entries *EntryConfig   `toml:"entries"`
	SOCKS5  *rawSOCKS5     `toml:"socks5"`
}

type rawSOCKS5 struct {
	URL      string `toml:"url"`
	Country  string `toml:"country"`
	City     string `toml:"city"`
	Sessions int    `toml:"sessions"`
}

func normalizeProviders(raw []rawProvider) ([]Provider, error) {
	if len(raw) == 0 {
		return nil, errors.New("config: providers must contain at least one provider")
	}
	providers := make([]Provider, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	mullvadCount := 0
	enabledCount := 0
	for _, entry := range raw {
		if entry.Enabled == nil {
			return nil, errors.New("config: provider enabled is required")
		}
		if entry.ID == "" || !isProviderToken(entry.ID) {
			return nil, errors.New("config: provider id is invalid")
		}
		if _, exists := seen[entry.ID]; exists {
			return nil, fmt.Errorf("config: duplicate provider id %q", entry.ID)
		}
		seen[entry.ID] = struct{}{}
		provider := Provider{id: entry.ID, enabled: *entry.Enabled, providerType: ProviderType(entry.Type)}
		switch provider.providerType {
		case ProviderMullvad:
			mullvadCount++
			if mullvadCount > 1 {
				return nil, errors.New("config: only one Mullvad provider is supported")
			}
			if entry.Catalog == nil || entry.Relays == nil || entry.Entries == nil {
				return nil, errors.New("config: Mullvad provider needs catalog, relays, and entries")
			}
			provider.mullvad = &MullvadConfig{Catalog: *entry.Catalog, Relays: *entry.Relays, Entries: *entry.Entries}
		case ProviderSOCKS5:
			if entry.SOCKS5 == nil {
				return nil, errors.New("config: socks5 provider needs socks5 settings")
			}
			parsed, err := parseSOCKS5Provider(*entry.SOCKS5)
			if err != nil {
				return nil, err
			}
			provider.country, provider.city, provider.sessions, provider.proxyURL = parsed.country, parsed.city, parsed.sessions, parsed.proxyURL
		default:
			return nil, fmt.Errorf("config: unsupported provider type %q", entry.Type)
		}
		if provider.enabled {
			enabledCount++
		}
		providers = append(providers, provider)
	}
	if enabledCount == 0 {
		return nil, errors.New("config: providers needs an enabled provider")
	}
	return providers, nil
}

type parsedSOCKS5 struct {
	country  string
	city     string
	sessions int
	proxyURL *url.URL
}

func parseSOCKS5Provider(entry rawSOCKS5) (parsedSOCKS5, error) {
	parsed, err := url.Parse(entry.URL)
	if err != nil || (parsed.Scheme != "socks5" && parsed.Scheme != "socks5h") || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User == nil {
		return parsedSOCKS5{}, errors.New("config: socks5 provider url is invalid")
	}
	username := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	if username == "" || !hasPassword || password == "" {
		return parsedSOCKS5{}, errors.New("config: socks5 provider url needs username and password")
	}
	if _, port, err := net.SplitHostPort(parsed.Host); err != nil {
		return parsedSOCKS5{}, errors.New("config: socks5 provider url needs a host and port")
	} else if number, parseErr := strconv.Atoi(port); parseErr != nil || number < 1 || number > 65535 {
		return parsedSOCKS5{}, errors.New("config: socks5 provider url has an invalid port")
	}
	country := strings.ToLower(entry.Country)
	city := strings.ToLower(entry.City)
	if country != "" && !isProviderCountry(country) {
		return parsedSOCKS5{}, errors.New("config: socks5 provider country is invalid")
	}
	if city != "" && !isProviderToken(city) {
		return parsedSOCKS5{}, errors.New("config: socks5 provider city is invalid")
	}
	if entry.Sessions < 0 || entry.Sessions > 10_000 {
		return parsedSOCKS5{}, errors.New("config: socks5 provider sessions must be between 0 and 10000")
	}
	return parsedSOCKS5{country: country, city: city, sessions: entry.Sessions, proxyURL: parsed}, nil
}

func isProviderToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isProviderCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'a' && value[0] <= 'z' && value[1] >= 'a' && value[1] <= 'z'
}
