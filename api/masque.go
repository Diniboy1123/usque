package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to use for TLS authentication.
//   - peerPubKey: *ecdsa.PublicKey - The endpoint's public key to pin to.
//   - cert: [][]byte - The certificate chain to use for TLS authentication.
//   - sni: string - The Server Name Indication (SNI) to use.
//   - insecure: bool - When true, skip endpoint public key pinning.
//
// Returns:
//   - *tls.Config: A TLS configuration for secure communication.
//   - error: An error if TLS setup fails.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// To avoid the Hello Retry Requests you would uncomment this, but I prefer to keep Go defaults, maybe
		// Cloudflare adds support for more curves in the future and I don't want to hardcode it here
		// NOTE: If I add more than one, Go will still use one share it picks and it was never P-256 for me
		// so kept it doing HRRs for now.
		// I couldn't get the official client to work with HTTP/2, so couldn't check its behavior.
		/*CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},*/
	}

	if !insecure {
		// we pin to the endpoint public key
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				// TODO: don't hardcode cert type in the future
				// as backend can start using different cert types
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				// reason is incorrect, but the best I could figure
				// detail explains the actual reason

				//10 is NoValidChains, but we support go1.22 where it's not defined
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		}
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a Connect-IP tunnel with the provided endpoint.
// When useHTTP2 is false it dials over QUIC/HTTP3; when true it dials over TCP/HTTP2.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
//
// Parameters:
//   - ctx: context.Context - The connection context.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings (ignored in HTTP/2 mode).
//   - connectUri: string - The URI template for the Connect-IP request.
//   - endpoint: net.Addr - The remote endpoint (*net.UDPAddr for HTTP/3, *net.TCPAddr for HTTP/2).
//   - useHTTP2: bool - When true, connect over TCP+TLS/HTTP2 instead of QUIC/HTTP3.
//
// Returns:
//   - *net.UDPConn: The UDP connection used for the QUIC session (nil in HTTP/2 mode).
//   - *http3.Transport: The HTTP/3 transport (nil in HTTP/2 mode).
//   - *connectip.Conn: The Connect-IP connection instance.
//   - *http.Response: The response from the Connect-IP handshake.
//   - error: An error if the connection setup fails.
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint net.Addr, useHTTP2 bool) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	template := uritemplate.MustNew(connectUri)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	if useHTTP2 {
		h2Endpoint, ok := endpoint.(*net.TCPAddr)
		if !ok || h2Endpoint == nil {
			return nil, nil, nil, nil, errors.New("missing HTTP/2 TCP endpoint")
		}

		h2Headers := additionalHeaders.Clone()
		h2Headers.Set("cf-connect-proto", "cf-connect-ip")
		// TODO: support PQC
		h2Headers.Set("pq-enabled", "false")

		h2Client, err := newHTTP2Client(tlsConfig, h2Endpoint, connectUri)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create HTTP/2 client: %w", err)
		}

		ipConn, rsp, err := connectip.DialH2(ctx, h2Client, template, h2Headers)
		if err != nil {
			if strings.Contains(err.Error(), "tls: access denied") {
				return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
			}
			return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", err)
		}
		return nil, nil, ipConn, rsp, nil
	}

	quicEndpoint, ok := endpoint.(*net.UDPAddr)
	if !ok || quicEndpoint == nil {
		return nil, nil, nil, nil, errors.New("missing HTTP/3 UDP endpoint")
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		udpConn, tr, ipConn, rsp, err := connectTunnelHTTP3(ctx, tlsConfig, quicConfig, template, additionalHeaders, quicEndpoint)
		if err == nil {
			return udpConn, tr, ipConn, rsp, nil
		}
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		lastErr = err
		if !isRetryableHTTP3ConnectFailure(err) {
			break
		}
	}
	return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %w", lastErr)
}

func connectTunnelHTTP3(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, template *uritemplate.Template, additionalHeaders http.Header, endpoint *net.UDPAddr) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	var udpConn *net.UDPConn
	var err error
	if endpoint.IP.To4() == nil {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		})
	} else {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		})
	}
	if err != nil {
		return udpConn, nil, nil, nil, err
	}

	// without ConnectionIDLength set, backend occasionally throws PROTOCOL_VIOLATION
	// and that closes our connection
	qtr := &quic.Transport{Conn: udpConn, ConnectionIDLength: 20}
	conn, err := qtr.Dial(ctx, endpoint, tlsConfig, quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		_ = udpConn.Close()
		return nil, nil, nil, nil, err
	}

	return udpConn, tr, ipConn, rsp, nil
}

func isRetryableHTTP3ConnectFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "failed to read response") &&
		strings.Contains(msg, "PROTOCOL_VIOLATION")
}

// newHTTP2Client builds an HTTP client for CONNECT-IP over HTTP/2.
// It honors proxy environment variables and pins dialing to the selected endpoint.
func newHTTP2Client(baseTLSConfig *tls.Config, endpoint *net.TCPAddr, connectURI string) (*http.Client, error) {
	if endpoint == nil {
		return nil, errors.New("missing HTTP/2 endpoint")
	}

	parsedURI, err := url.Parse(connectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connect URI: %w", err)
	}

	proxyURL, _ := http.ProxyFromEnvironment(&http.Request{URL: parsedURI})

	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	verifyConnection := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if verifyConnection != nil {
			if err := verifyConnection(state); err != nil {
				return err
			}
		}
		if state.NegotiatedProtocol != "h2" {
			return errors.New("CONNECT-IP requires HTTP/2 ALPN")
		}
		return nil
	}

	if proxyURL == nil {
		transport := &http.Transport{
			ForceAttemptHTTP2: true,
			DisableKeepAlives: true,
			TLSClientConfig:   tlsConfig,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := &net.Dialer{}
				conn, err := dialer.DialContext(ctx, network, endpoint.String())
				if err != nil {
					return nil, err
				}

				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}

		return &http.Client{Transport: transport}, nil
	}

	originAuthority := authorityWithDefaultPort(parsedURI, "443")
	proxyAuthority := authorityWithDefaultPort(proxyURL, proxyDefaultPort(proxyURL))
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		ForceAttemptHTTP2:  true,
		DisableKeepAlives:  true,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == originAuthority {
				addr = endpoint.String()
			}
			return dialer.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAddr := addr
			dialTLSConfig := tlsConfig
			if addr == proxyAuthority && proxyURL != nil {
				dialTLSConfig = &tls.Config{ServerName: proxyURL.Hostname()}
			} else if addr == originAuthority {
				dialAddr = endpoint.String()
			}

			conn, err := dialer.DialContext(ctx, network, dialAddr)
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, dialTLSConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	return &http.Client{Transport: transport}, nil
}

// authorityWithDefaultPort normalizes URL authority by adding a default port when missing.
func authorityWithDefaultPort(u *url.URL, defaultPort string) string {
	if u == nil {
		return ""
	}

	host := u.Hostname()
	if host == "" {
		return u.Host
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	}

	return net.JoinHostPort(host, port)
}

// proxyDefaultPort returns the default port for proxy scheme.
func proxyDefaultPort(u *url.URL) string {
	if u != nil && u.Scheme == "https" {
		return "443"
	}
	return "80"
}
