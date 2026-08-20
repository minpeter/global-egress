package pool

import (
	"context"
	"errors"
	"net"
	"net/url"

	"github.com/minpeter/global-egress/internal/catalog"
)

// Dialer is anything that can open a TCP connection, which is all the pool needs
// from a tunnel or a proxy chain.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Kind distinguishes the ways an egress slot can reach the internet.
type Kind int

const (
	// KindWireGuard is a slot backed by its own WireGuard tunnel.
	KindWireGuard Kind = iota
	// KindRelaySocks is a provider SOCKS proxy reached through an entry tunnel.
	KindRelaySocks
	// KindDirectSocks is a direct authenticated external SOCKS proxy.
	KindDirectSocks
)

func (k Kind) String() string {
	switch k {
	case KindWireGuard:
		return "wireguard"
	case KindRelaySocks:
		return "relay-socks"
	case KindDirectSocks:
		return "direct-socks"
	default:
		return "unknown"
	}
}

// Spec describes one selectable egress.
type Spec struct {
	// ID is unique within the pool.
	ID string
	// Country is an optional ISO-3166-1 alpha-2 location hint.
	Country string
	// City is an optional "<country>-<city>" location hint.
	City string
	// Provider is the non-secret policy selector.
	Provider string
	// Kind selects how the slot is reached.
	Kind Kind
	// WG carries the tunnel configuration for a WireGuard slot.
	WG catalog.Slot
	// SocksAddr is the proxy host:port for SOCKS-backed slots.
	SocksAddr     string
	socksUsername string
	socksPassword string
}

// Target returns the address this slot is reached at, without credentials.
func (s Spec) Target() string {
	if s.Kind == KindRelaySocks || s.Kind == KindDirectSocks {
		return s.SocksAddr
	}
	return s.WG.Endpoint
}

// SpecsFromBundle turns a WireGuard bundle into one slot per configuration.
func SpecsFromBundle(bundle *catalog.Bundle) []Spec {
	if bundle == nil {
		return nil
	}
	specs := make([]Spec, 0, len(bundle.Slots))
	for _, slot := range bundle.Slots {
		specs = append(specs, Spec{
			ID: slot.ID, Country: slot.Country, City: slot.City, Provider: "mullvad",
			Kind: KindWireGuard, WG: slot,
		})
	}
	return specs
}

// ExitSpec is provider-neutral information for one relay SOCKS exit.
type ExitSpec struct {
	// ID must be unique within the pool.
	ID string
	// Country is an optional location hint.
	Country string
	// City is an optional location hint.
	City string
	// Provider is the non-secret provider policy ID; empty means Mullvad.
	Provider string
	// SocksAddr is the proxy host:port, resolvable through an entry tunnel.
	SocksAddr string
}

// SpecsFromExits turns relay proxy exits into shared-entry slots.
func SpecsFromExits(exits []ExitSpec) []Spec {
	specs := make([]Spec, 0, len(exits))
	for _, exit := range exits {
		provider := exit.Provider
		if provider == "" {
			provider = "mullvad"
		}
		specs = append(specs, Spec{
			ID: exit.ID, Country: exit.Country, City: exit.City, Provider: provider,
			Kind: KindRelaySocks, SocksAddr: exit.SocksAddr,
		})
	}
	return specs
}

// DirectSocksOptions contains one external SOCKS provider for a direct slot.
type DirectSocksOptions struct {
	// ID is the provider and policy selector.
	ID string
	// Country and City are optional selection hints.
	Country string
	City    string
	// URL carries the authenticated endpoint from private config memory.
	URL *url.URL
}

// NewDirectSocksSpec creates a direct authenticated SOCKS slot while keeping
// credentials out of the public Spec fields and inventory.
func NewDirectSocksSpec(options DirectSocksOptions) (Spec, error) {
	if options.ID == "" || options.URL == nil || options.URL.User == nil {
		return Spec{}, errors.New("pool: direct SOCKS provider is incomplete")
	}
	username := options.URL.User.Username()
	password, hasPassword := options.URL.User.Password()
	if username == "" || !hasPassword || password == "" {
		return Spec{}, errors.New("pool: direct SOCKS provider needs credentials")
	}
	host, port, err := net.SplitHostPort(options.URL.Host)
	if err != nil || host == "" || port == "" {
		return Spec{}, errors.New("pool: direct SOCKS provider needs a host and port")
	}
	return Spec{
		ID: options.ID, Provider: options.ID, Country: options.Country, City: options.City,
		Kind: KindDirectSocks, SocksAddr: options.URL.Host,
		socksUsername: username, socksPassword: password,
	}, nil
}
