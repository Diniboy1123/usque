package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func newTestPrivateKey(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), key
}

func TestConfigMethodsUseReceiver(t *testing.T) {
	receiverKey, receiverPrivate := newTestPrivateKey(t)
	globalKey, _ := newTestPrivateKey(t)
	previous := AppConfig
	defer func() { AppConfig = previous }()
	AppConfig = Config{PrivateKey: globalKey, ID: "global"}

	receiver := Config{PrivateKey: receiverKey, ID: "receiver"}
	gotKey, err := receiver.GetEcPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !gotKey.PublicKey.Equal(&receiverPrivate.PublicKey) {
		t.Fatal("GetEcPrivateKey did not use the receiver")
	}

	path := filepath.Join(t.TempDir(), "config.json")
	if err := receiver.SaveConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved Config
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ID != receiver.ID {
		t.Fatalf("SaveConfig wrote ID %q; want %q", saved.ID, receiver.ID)
	}
}

func TestGetEcEndpointPublicKeyUsesReceiver(t *testing.T) {
	_, receiverPrivate := newTestPrivateKey(t)
	_, globalPrivate := newTestPrivateKey(t)
	receiverDER, err := x509.MarshalPKIXPublicKey(&receiverPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	globalDER, err := x509.MarshalPKIXPublicKey(&globalPrivate.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	previous := AppConfig
	defer func() { AppConfig = previous }()
	AppConfig = Config{EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: globalDER}))}

	receiver := Config{EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: receiverDER}))}
	gotKey, err := receiver.GetEcEndpointPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !gotKey.Equal(&receiverPrivate.PublicKey) {
		t.Fatal("GetEcEndpointPublicKey did not use the receiver")
	}
}
