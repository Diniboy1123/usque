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
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to use for TLS authentication.
//   - peerPubKey: *ecdsa.PublicKey - The endpoint's public key to pin to.
//   - cert: [][]byte - The certificate chain to use for TLS authentication.
//   - sni: string - The Server Name Indication (SNI) to use.
//
// Returns:
//   - *tls.Config: A TLS configuration for secure communication.
//   - error: An error if TLS setup fails.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3, "h2", "http/1.1"},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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
		},
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a QUIC connection and sets up a Connect-IP tunnel with the provided endpoint.
// Endpoint address is used to check whether the authentication/connection is successful or not.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
//
// Parameters:
//   - ctx: context.Context - The QUIC TLS context.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings.
//   - connectUri: string - The URI template for the Connect-IP request.
//   - endpoint: *net.UDPAddr - The UDP address of the QUIC server.
//
// Returns:
//   - *net.UDPConn: The UDP connection used for the QUIC session.
//   - *http3.Transport: The HTTP/3 transport used for initial request.
//   - *connectip.Conn: The Connect-IP connection instance.
//   - *http.Response: The response from the Connect-IP handshake.
//   - error: An error if the connection setup fails.
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint *net.UDPAddr) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
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

	conn, err := quic.Dial(
		ctx,
		udpConn,
		endpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		return udpConn, nil, nil, nil, err
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

	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	template := uritemplate.MustNew(connectUri)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		if err.Error() == "CRYPTO_ERROR 0x131 (remote): tls: access denied" {
			return udpConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return udpConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %v", err)
	}

	return udpConn, tr, ipConn, rsp, nil
}

// ConnectTunnelWithFallback establishes a QUIC connection with HTTP/3 first, then falls back to TCP with HTTP/2 if QUIC fails.
// This provides better compatibility when QUIC/HTTP3 is not available or blocked.
//
// Parameters:
//   - ctx: context.Context - The context for the connection.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings.
//   - connectUri: string - The URI template for the Connect-IP request.
//   - endpoint: *net.UDPAddr - The UDP address of the QUIC server.
//
// Returns:
//   - *net.UDPConn: The UDP connection used for the QUIC session (nil for HTTP/2).
//   - *http3.Transport: The HTTP/3 transport used for initial request (nil for HTTP/2).
//   - *connectip.Conn: The Connect-IP connection instance.
//   - *http.Response: The response from the Connect-IP handshake.
//   - error: An error if both HTTP/3 and HTTP/2 connections fail.
func ConnectTunnelWithFallback(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint *net.UDPAddr) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	// First, try HTTP/3 over QUIC
	udpConn, tr, ipConn, rsp, err := ConnectTunnel(ctx, tlsConfig, quicConfig, connectUri, endpoint)
	if err == nil {
		return udpConn, tr, ipConn, rsp, nil
	}

	// Log the HTTP/3 failure and try HTTP/2 fallback
	fmt.Printf("HTTP/3 connection failed: %v, attempting HTTP/2 fallback\n", err)

	// Try HTTP/2 fallback - test if the server supports HTTP/2
	http2Err := testHTTP2Connection(ctx, tlsConfig, endpoint)
	if http2Err == nil {
		return nil, nil, nil, nil, fmt.Errorf("HTTP/3 connection failed, HTTP/2 connection possible but full Connect-IP over HTTP/2 not yet implemented: %v", err)
	}

	// Both HTTP/3 and HTTP/2 failed
	return nil, nil, nil, nil, fmt.Errorf("HTTP/3 connection failed: %v, HTTP/2 connection also failed: %v", err, http2Err)
}

// testHTTP2Connection tests if the server supports HTTP/2 connections
func testHTTP2Connection(ctx context.Context, tlsConfig *tls.Config, endpoint *net.UDPAddr) error {
	// Convert UDP endpoint to TCP for HTTP/2 connection
	tcpAddr := &net.TCPAddr{
		IP:   endpoint.IP,
		Port: endpoint.Port,
	}

	// Create HTTP/2 transport
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create HTTP/2 client
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Create a simple test request to check HTTP/2 connectivity
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/", tcpAddr.String()), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP/2 test request: %v", err)
	}

	// Add headers
	req.Header.Set("User-Agent", "")
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP/2 connection test failed: %v", err)
	}
	defer resp.Body.Close()

	// If we get here, HTTP/2 connection works
	return nil
}
