package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Diniboy1123/usque/internal"
)

func waitForSocketClose(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(4 * time.Second):
		t.Fatal("HTTP/2 tunnel socket remained open after stream completion")
	}
}

func tunnelTestServer(t *testing.T, handler http.Handler, h2 bool) (*tls.Config, *net.TCPAddr, <-chan struct{}) {
	t.Helper()
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = h2
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	cfg, err := PrepareTlsConfig(key, &key.PublicKey, [][]byte{der}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, server.Listener.Addr().(*net.TCPAddr), closed
}

func TestHTTP2TunnelStreamCloseReleasesSocket(t *testing.T) {
	cfg, endpoint, closed := tunnelTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("negotiated HTTP/%d, expected HTTP/2", r.ProtoMajor)
		}
		if r.TLS.ServerName != "" {
			t.Errorf("empty SNI changed to %q", r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, r.Body)
	}), true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, conn, _, err := ConnectTunnel(ctx, cfg, nil, internal.ConnectURI, endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitForSocketClose(t, closed)
}

func TestHTTP2RejectedTunnelReleasesSocket(t *testing.T) {
	cfg, endpoint, closed := tunnelTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }), true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, conn, _, err := ConnectTunnel(ctx, cfg, nil, internal.ConnectURI, endpoint, true)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("rejected CONNECT unexpectedly succeeded")
	}
	waitForSocketClose(t, closed)
}

func TestHTTP2TunnelRejectsWrongPin(t *testing.T) {
	cfg, endpoint, _ := tunnelTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the server with an incorrect endpoint pin")
	}), true)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := cfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	cfg, err = PrepareTlsConfig(key, &other.PublicKey, cfg.Certificates[0].Certificate, "", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, conn, _, err := ConnectTunnel(ctx, cfg, nil, internal.ConnectURI, endpoint, true)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "different public key") {
		t.Fatalf("wrong endpoint pin error=%v", err)
	}
}

func TestHTTP2TunnelRejectsHTTP1(t *testing.T) {
	cfg, endpoint, _ := tunnelTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP/1 CONNECT reached the server") }), false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, conn, _, err := ConnectTunnel(ctx, cfg, nil, internal.ConnectURI, endpoint, true)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "requires HTTP/2 ALPN") {
		t.Fatalf("HTTP/1 fallback error=%v", err)
	}
}
