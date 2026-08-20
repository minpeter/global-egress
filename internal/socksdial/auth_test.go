package socksdial

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestDialAuthenticatedSocks5UsesRFC1929(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	authenticated := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, readErr := io.ReadFull(conn, greeting); readErr != nil {
			return
		}
		if greeting[0] != version || greeting[1] != 1 || greeting[2] != methodUsernamePassword {
			return
		}
		_, _ = conn.Write([]byte{version, methodUsernamePassword})
		header := make([]byte, 2)
		if _, readErr := io.ReadFull(conn, header); readErr != nil {
			return
		}
		username := make([]byte, int(header[1]))
		if _, readErr := io.ReadFull(conn, username); readErr != nil {
			return
		}
		passwordLength := []byte{0}
		if _, readErr := io.ReadFull(conn, passwordLength); readErr != nil {
			return
		}
		password := make([]byte, int(passwordLength[0]))
		if _, readErr := io.ReadFull(conn, password); readErr != nil {
			return
		}
		if string(username) != "dummy-user" || string(password) != "dummy-pass" {
			return
		}
		_, _ = conn.Write([]byte{authVersion, authSuccess})
		request := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			return
		}
		if request[3] != atypDomain {
			return
		}
		nameLength := []byte{0}
		if _, readErr := io.ReadFull(conn, nameLength); readErr != nil {
			return
		}
		name := make([]byte, int(nameLength[0]))
		if _, readErr := io.ReadFull(conn, name); readErr != nil || string(name) != "example.com" {
			return
		}
		port := make([]byte, 2)
		_, _ = io.ReadFull(conn, port)
		response := []byte{version, replySuccess, 0, atypIPv4, 127, 0, 0, 1, 0, 80}
		_, _ = conn.Write(response)
		binary.BigEndian.PutUint16(port, 80)
		close(authenticated)
	}()

	dialer := &Dialer{Base: &net.Dialer{}, ProxyAddr: listener.Addr().String(), Username: "dummy-user", Password: "dummy-pass"}
	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()
	select {
	case <-authenticated:
	case <-t.Context().Done():
		t.Fatal("authenticated SOCKS negotiation was not observed")
	}
}
