package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/pool"
)

// SOCKS5 wire constants.
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	userPassVersion = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repHostUnreachable     = 0x04
	repConnectionRefused   = 0x05
	repCommandNotSupported = 0x07
	repAddrNotSupported    = 0x08
)

// handshakeTimeout bounds the SOCKS negotiation, before relaying starts.
const handshakeTimeout = 30 * time.Second

// SOCKS5Server serves the pool over SOCKS5.
//
// Only CONNECT is implemented. BIND has no meaning here, and UDP ASSOCIATE would
// require a UDP path through the tunnel that the netstack dialer does not expose
// for arbitrary peers; QUIC clients therefore fall back to TCP.
type SOCKS5Server struct {
	deps *Deps
}

// NewSOCKS5 builds a SOCKS5 server.
func NewSOCKS5(deps Deps) *SOCKS5Server {
	deps.applyDefaults()
	return &SOCKS5Server{deps: &deps}
}

// Serve accepts connections until the listener is closed.
func (s *SOCKS5Server) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// The listener was closed because we are shutting down, which is a
				// normal end of service rather than a failure.
				return nil //nolint:nilerr // shutdown, not an error
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

func (s *SOCKS5Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	log := s.deps.Logger.With(slog.String("proto", "socks5"))

	if err := s.deps.checkClient(client.RemoteAddr()); err != nil {
		log.Warn("client rejected", errorTypeAttr(err))
		return
	}

	_ = client.SetDeadline(time.Now().Add(handshakeTimeout))

	pol, err := s.negotiate(client)
	if err != nil {
		// SOCKS5 has no way to explain a rejection to the client, so a policy
		// refusal has to be visible to the operator instead: it almost always means
		// a caller dropped its credentials rather than an attack.
		if errors.Is(err, errPolicyRequired) {
			log.Warn("rejected: no selection policy supplied")
		} else {
			// Policy parse failures can echo attacker-supplied directives, including
			// malformed addresses, so do not reflect their text into logs.
			log.Debug("negotiation failed")
		}
		return
	}

	host, port, err := readRequest(client)
	if err != nil {
		log.Debug("bad request", errorTypeAttr(err))
		return
	}

	started := time.Now()
	upstream, lease, err := s.deps.connectUpstream(ctx, pol, host, port)
	if err != nil {
		s.deps.observeRequestPhase(
			pol, lease, requestResult(err), pool.TimeoutPhaseAcquire, time.Since(started))
		log.Warn("connect failed",
			policyLogAttr(pol),
			errorTypeAttr(err))
		_ = writeReply(client, replyCodeFor(err), nil)
		return
	}
	s.deps.observeRequest(pol, lease, pool.RequestSuccess, time.Since(started))
	defer lease.Release()
	defer upstream.Close()

	if err := writeReply(client, repSuccess, upstream.LocalAddr()); err != nil {
		log.Debug("reply failed", errorTypeAttr(err))
		return
	}

	// Relaying manages its own deadlines from here on.
	_ = client.SetDeadline(time.Time{})

	started = time.Now()
	sent, received := relay(client, upstream, s.deps.IdleTimeout)
	s.deps.Pool.RecordTraffic(lease, sent, received)
	log.Info("session finished",
		slog.String("slot", lease.Slot.ID),
		slog.Bool("egress_ip_measured", lease.PublicIP.IsValid()),
		policyLogAttr(pol),
		slog.Int64("sent", sent),
		slog.Int64("received", received),
		slog.Duration("duration", time.Since(started)))
}

// negotiate performs method selection and optional username/password auth.
func (s *SOCKS5Server) negotiate(client net.Conn) (pol policy.Policy, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return pol, err
	}
	if header[0] != socksVersion {
		return pol, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return pol, err
	}

	offersUserPass := false
	offersNoAuth := false
	for _, method := range methods {
		switch method {
		case methodUserPass:
			offersUserPass = true
		case methodNoAuth:
			offersNoAuth = true
		}
	}

	// Prefer username/password whenever the client offers it: that is how the
	// selection policy reaches us.
	switch {
	case offersUserPass:
		if _, err := client.Write([]byte{socksVersion, methodUserPass}); err != nil {
			return pol, err
		}
		username, password, err := readUserPass(client)
		if err != nil {
			return pol, err
		}
		parsed, authErr := s.deps.authorize(username, password, true)
		if authErr != nil {
			// 0x01 tells the client the credentials were rejected.
			_, _ = client.Write([]byte{userPassVersion, 0x01})
			return pol, authErr
		}
		if _, err := client.Write([]byte{userPassVersion, 0x00}); err != nil {
			return pol, err
		}
		return parsed, nil

	case offersNoAuth:
		parsed, authErr := s.deps.authorize("", "", false)
		if authErr != nil {
			_, _ = client.Write([]byte{socksVersion, methodNoAcceptable})
			return pol, authErr
		}
		if _, err := client.Write([]byte{socksVersion, methodNoAuth}); err != nil {
			return pol, err
		}
		return parsed, nil

	default:
		_, _ = client.Write([]byte{socksVersion, methodNoAcceptable})
		return pol, errors.New("no acceptable authentication method")
	}
}

func readUserPass(client net.Conn) (username, password string, err error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", "", err
	}
	if header[0] != userPassVersion {
		return "", "", fmt.Errorf("unsupported auth version %d", header[0])
	}
	buf := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, buf); err != nil {
		return "", "", err
	}
	username = string(buf)

	lengthByte := make([]byte, 1)
	if _, err := io.ReadFull(client, lengthByte); err != nil {
		return "", "", err
	}
	buf = make([]byte, int(lengthByte[0]))
	if _, err := io.ReadFull(client, buf); err != nil {
		return "", "", err
	}
	return username, string(buf), nil
}

// readRequest parses a CONNECT request and returns the destination.
func readRequest(client net.Conn) (host string, port int, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(client, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion {
		return "", 0, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	if header[1] != cmdConnect {
		_ = writeReply(client, repCommandNotSupported, nil)
		return "", 0, fmt.Errorf("unsupported command %d", header[1])
	}

	switch header[3] {
	case atypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(client, lengthByte); err != nil {
			return "", 0, err
		}
		buf := make([]byte, int(lengthByte[0]))
		if _, err := io.ReadFull(client, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	default:
		_ = writeReply(client, repAddrNotSupported, nil)
		return "", 0, fmt.Errorf("unsupported address type %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(portBuf))
	if host == "" || port == 0 {
		return "", 0, errors.New("empty destination")
	}
	return host, port, nil
}

// writeReply sends a SOCKS5 reply. bound may be nil, in which case 0.0.0.0:0 is
// reported, which clients accept for CONNECT.
func writeReply(client net.Conn, code byte, bound net.Addr) error {
	reply := []byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	if bound != nil {
		if tcpAddr, ok := bound.(*net.TCPAddr); ok && tcpAddr.IP != nil {
			if v4 := tcpAddr.IP.To4(); v4 != nil {
				copy(reply[4:8], v4)
				binary.BigEndian.PutUint16(reply[8:10], uint16(tcpAddr.Port))
			} else if v6 := tcpAddr.IP.To16(); v6 != nil {
				reply = append([]byte{socksVersion, code, 0x00, atypIPv6}, v6...)
				portBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(portBytes, uint16(tcpAddr.Port))
				reply = append(reply, portBytes...)
			}
		}
	}
	_, err := client.Write(reply)
	return err
}
