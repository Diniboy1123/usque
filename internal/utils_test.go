package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestGenerateCertUsesProvidedPublicKey(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expectedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := GenerateCert(signingKey, &expectedKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key has type %T", cert.PublicKey)
	}
	if !publicKey.Equal(&expectedKey.PublicKey) {
		t.Fatal("certificate did not use the provided public key")
	}
}
