// Package socksdial is a minimal SOCKS5 client used to chain through a proxy
// that is only reachable over another dialer.
//
// The provider exposes a SOCKS proxy on every relay, but those proxies resolve
// and answer only from inside the provider network. So the base dialer here is
// normally a WireGuard tunnel: connect through the tunnel to the relay's proxy,
// then ask that proxy to reach the real destination. The destination therefore
// sees the relay's address, while only one tunnel is ever established.
package socksdial

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 wire constants, per RFC 1928.
const (
	version                = 0x05
	methodNoAuth           = 0x00
	methodUsernamePassword = 0x02
	authVersion            = 0x01
	authSuccess            = 0x00
	cmdConnect             = 0x01
	atypIPv4               = 0x01
	atypDomain             = 0x03
	atypIPv6               = 0x04
	replySuccess           = 0x00
)

// ErrDestination is returned when the SOCKS proxy was reached successfully but
// refused the requested destination. Callers can use it to avoid blaming the
// path to the proxy for an origin-side failure.
var ErrDestination = errors.New("socksdial: destination refused")

// Dialer connects to destinations through a SOCKS5 proxy.
type Dialer struct {
	// Base opens the connection to the proxy itself.
	Base ContextDialer
	// ProxyAddr is the proxy's "host:port".
	ProxyAddr string
	// Timeout bounds the SOCKS negotiation once the proxy is connected. Zero
	// means the context deadline alone applies.
	Timeout time.Duration
	// Username and Password enable RFC1929 authentication when both are set.
	Username string
	Password string
}

// ContextDialer is the subset of net.Dialer that Base must provide.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContext connects to address through the proxy. Host names are passed to
// the proxy unresolved, so DNS happens at the exit rather than locally.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socksdial: unsupported network %q", network)
	}
	if d.Base == nil {
		return nil, errors.New("socksdial: no base dialer")
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("socksdial: invalid address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socksdial: invalid port in %q", address)
	}

	conn, err := d.Base.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socksdial: connect proxy %s: %w", d.ProxyAddr, err)
	}

	if err := d.negotiate(ctx, conn, host, port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) negotiate(ctx context.Context, conn net.Conn, host string, port int) error {
	// Apply whichever bound is tighter: the caller's deadline or ours.
	deadline, hasDeadline := ctx.Deadline()
	if d.Timeout > 0 {
		own := time.Now().Add(d.Timeout)
		if !hasDeadline || own.Before(deadline) {
			deadline, hasDeadline = own, true
		}
	}
	if hasDeadline {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("socksdial: set deadline: %w", err)
		}
		// Clear it again so the caller owns the connection's timing afterwards.
		defer func() { _ = conn.SetDeadline(time.Time{}) }()
	}

	methods := []byte{methodNoAuth}
	if d.Username != "" || d.Password != "" {
		if len(d.Username) > 255 || len(d.Password) > 255 || d.Username == "" || d.Password == "" {
			return errors.New("socksdial: username and password must be 1-255 bytes")
		}
		methods = []byte{methodUsernamePassword}
	}
	if _, err := conn.Write(append([]byte{version, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socksdial: write greeting: %w", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socksdial: read greeting reply: %w", err)
	}
	if reply[0] != version {
		return fmt.Errorf("socksdial: proxy %s answered SOCKS version %d", d.ProxyAddr, reply[0])
	}
	if reply[1] == methodUsernamePassword && d.Username != "" && d.Password != "" {
		auth := []byte{authVersion, byte(len(d.Username))}
		auth = append(auth, d.Username...)
		auth = append(auth, byte(len(d.Password)))
		auth = append(auth, d.Password...)
		if _, err := conn.Write(auth); err != nil {
			return fmt.Errorf("socksdial: write username/password: %w", err)
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return fmt.Errorf("socksdial: read username/password reply: %w", err)
		}
		if authReply[0] != authVersion || authReply[1] != authSuccess {
			return errors.New("socksdial: proxy rejected username/password")
		}
	} else if reply[1] != methodNoAuth {
		return fmt.Errorf("socksdial: proxy %s selected unsupported authentication method 0x%02x", d.ProxyAddr, reply[1])
	} else if d.Username != "" || d.Password != "" {
		return errors.New("socksdial: proxy selected unauthenticated access")
	}

	request, err := buildConnect(host, port)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socksdial: write connect request: %w", err)
	}
	return readConnectReply(conn)
}

func buildConnect(host string, port int) ([]byte, error) {
	request := []byte{version, cmdConnect, 0x00}

	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, atypIPv4)
			request = append(request, v4...)
		} else {
			request = append(request, atypIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socksdial: host name %q is too long for SOCKS5", host)
		}
		request = append(request, atypDomain, byte(len(host)))
		request = append(request, host...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	return append(request, portBytes...), nil
}

func readConnectReply(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("socksdial: read connect reply: %w", err)
	}
	if header[0] != version {
		return fmt.Errorf("socksdial: bad reply version %d", header[0])
	}
	if header[1] != replySuccess {
		return fmt.Errorf("%w: %s", ErrDestination, replyMessage(header[1]))
	}

	// Consume the bound address so the stream starts at the payload.
	switch header[3] {
	case atypIPv4:
		if _, err := io.ReadFull(conn, make([]byte, net.IPv4len+2)); err != nil {
			return fmt.Errorf("socksdial: read bound address: %w", err)
		}
	case atypIPv6:
		if _, err := io.ReadFull(conn, make([]byte, net.IPv6len+2)); err != nil {
			return fmt.Errorf("socksdial: read bound address: %w", err)
		}
	case atypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("socksdial: read bound name length: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(length[0])+2)); err != nil {
			return fmt.Errorf("socksdial: read bound name: %w", err)
		}
	default:
		return fmt.Errorf("socksdial: unknown address type %d in reply", header[3])
	}
	return nil
}

// replyMessage translates a SOCKS5 reply code into something readable.
func replyMessage(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("code 0x%02x", code)
	}
}
