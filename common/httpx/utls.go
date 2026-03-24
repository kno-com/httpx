package httpx

import (
	"context"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// dialUTLS performs a TCP dial followed by a uTLS handshake using a Chrome fingerprint.
// ALPN is forced to "http/1.1" so the connection is not mistaken for HTTP/2 by
// the standard library transport (which type-asserts *tls.Conn, not *utls.UConn).
func dialUTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("utls: dial tcp: %w", err)
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS10,
	}, utls.HelloChrome_Auto)

	if err := tlsConn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls: build handshake state: %w", err)
	}

	for _, ext := range tlsConn.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls: tls handshake: %w", err)
	}

	return tlsConn, nil
}
