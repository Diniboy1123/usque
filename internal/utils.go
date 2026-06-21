package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// PortMapping represents a network port forwarding rule.
type PortMapping struct {
	BindAddress string // The address to bind the local port.
	LocalPort   int    // The local port number.
	RemoteIP    string // The remote destination IP address.
	RemotePort  int    // The remote destination port number.
}

// GenerateRandomAndroidSerial generates a random 8-byte Android-like device identifier
// and returns it as a hexadecimal string.
//
// Returns:
//   - string: A randomly generated 16-character hexadecimal serial number.
//   - error:  An error if random data generation fails.
func GenerateRandomAndroidSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random 32-byte WireGuard like public key
// and returns it as a base64-encoded string.
//
// Returns:
//   - string: A randomly generated WireGuard like public key in base64 format.
//   - error:  An error if random data generation fails.
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// TimeAsCfString formats a given time.Time into a Cloudflare-compatible string format.
//
// The format follows the standard: "YYYY-MM-DDTHH:MM:SS.sss-07:00".
//
// Parameters:
//   - t: time.Time to format.
//
// Returns:
//   - string: The formatted time string.
func TimeAsCfString(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

// GenerateEcKeyPair generates a new ECDSA key pair using the P-256 curve.
//
// Returns:
//   - []byte: The marshalled private key in ASN.1 DER format.
//   - []byte: The marshalled public key in PKIX format.
//   - error:  An error if key generation or marshalling fails.
func GenerateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// GenerateCert creates a self-signed certificate using the provided ECDSA private and public keys.
//
// The certificate is valid for 24 hours.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to sign the certificate.
//   - pubKey: *ecdsa.PublicKey - The public key to include in the certificate.
//
// Returns:
//   - [][]byte: A slice containing the certificate in DER format.
//   - error:    An error if certificate generation fails.
func GenerateCert(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{cert}, nil
}

// DefaultQuicConfig returns a MASQUE-compatible default QUIC configuration.
//
// When initialPacketSize is 0, Path MTU Discovery remains enabled.
//
// Parameters:
//   - keepalivePeriod: time.Duration - The duration for sending QUIC keep-alive packets.
//   - initialPacketSize: uint16 - The custom initial size of QUIC packets (0 = auto with PMTU discovery).
//
// Returns:
//   - *quic.Config: A pointer to a configured QUIC configuration object.
func DefaultQuicConfig(keepalivePeriod time.Duration, initialPacketSize uint16) *quic.Config {
	cfg := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: keepalivePeriod,
		Congestion: func() quic.SendAlgorithmWithDebugInfos{return quic.NewBBRv1(&quic.Config{})},
	}

	if initialPacketSize > 0 {
		cfg.InitialPacketSize = initialPacketSize
		cfg.DisablePathMTUDiscovery = true
	}

	return cfg
}

// parsePortMapping is an internal helper function that parses a port mapping string into its components.
//
// It handles IPv6 addresses enclosed in brackets and various format edge cases.
//
// Parameters:
//   - port: string - The port mapping string.
//
// Returns:
//   - string: The bind address.
//   - int: The local port.
//   - string: The remote hostname/IP.
//   - int: The remote port.
//   - error: An error if parsing fails.
func parsePortMapping(port string) (bindAddress string, localPort int, remoteHost string, remotePort int, err error) {
	parts := strings.Split(port, ":")

	// Handle IPv6 addresses (which are enclosed in brackets)
	if len(parts) >= 4 && strings.HasPrefix(parts[0], "[") && strings.Contains(parts[0], "]") {
		bindAddress = parts[0]
		parts = parts[1:] // Shift parts forward
	} else if len(parts) == 3 {
		bindAddress = "localhost" // Default to localhost
	} else if len(parts) == 4 {
		bindAddress = parts[0]
		parts = parts[1:] // Shift forward
	} else {
		return "", 0, "", 0, errors.New("invalid port mapping format (expected format: [bind_address:]local_port:remote_host:remote_port)")
	}

	// Parse local port
	localPort, err = strconv.Atoi(parts[0])
	if err != nil || localPort <= 0 || localPort > 65535 {
		return "", 0, "", 0, errors.New("invalid local port")
	}

	// Validate remote host (allow both hostnames and IPs)
	remoteHost = parts[1]
	if net.ParseIP(remoteHost) == nil && !isValidHostname(remoteHost) {
		return "", 0, "", 0, errors.New("invalid remote hostname/IP")
	}

	// Parse remote port
	remotePort, err = strconv.Atoi(parts[2])
	if err != nil || remotePort <= 0 || remotePort > 65535 {
		return "", 0, "", 0, errors.New("invalid remote port")
	}

	// If bindAddress is an IPv6 address, remove brackets for proper binding
	if strings.HasPrefix(bindAddress, "[") && strings.HasSuffix(bindAddress, "]") {
		bindAddress = strings.Trim(bindAddress, "[]")
	}

	// Convert "localhost" or hostnames to actual addresses
	if bindAddress == "*" {
		bindAddress = "0.0.0.0" // Allow all interfaces
	}

	// Validate bind address (support both IPs and hostnames)
	bindAddress, err = resolveBindAddress(bindAddress)
	if err != nil {
		return "", 0, "", 0, errors.New("invalid local address: " + err.Error())
	}

	remoteHost, err = resolveBindAddress(remoteHost)
	if err != nil {
		return "", 0, "", 0, errors.New("invalid remote address: " + err.Error())
	}

	return bindAddress, localPort, remoteHost, remotePort, nil
}

// ParsePortMapping parses a port mapping string into a structured PortMapping.
//
// The expected format is: `[bind_address:]local_port:remote_host:remote_port`.
//
// Parameters:
//   - port: string - The port mapping string.
//
// Returns:
//   - PortMapping: A structured representation of the parsed port mapping.
//   - error:       An error if the parsing fails.
func ParsePortMapping(port string) (PortMapping, error) {
	bindAddress, localPort, remoteHost, remotePort, err := parsePortMapping(port)
	if err != nil {
		return PortMapping{}, err
	}

	return PortMapping{
		BindAddress: bindAddress,
		LocalPort:   localPort,
		RemoteIP:    remoteHost,
		RemotePort:  remotePort,
	}, nil
}

// resolveBindAddress resolves a hostname or IP to its string representation.
//
// Parameters:
//   - addr: string - The hostname or IP.
//
// Returns:
//   - string: The resolved IP address.
//   - error:  An error if resolution fails.
func resolveBindAddress(addr string) (string, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr+":0") // Resolve the address
	if err != nil {
		return "", err
	}
	return tcpAddr.IP.String(), nil // Return resolved IP
}

// isValidHostname checks if a given hostname is valid.
// Pretty ugly for now, needs to be refactored.
//
// Parameters:
//   - hostname: string - The hostname to validate.
//
// Returns:
//   - bool: True if valid, false otherwise.
func isValidHostname(hostname string) bool {
	// Must contain at least one dot (.) unless it's "localhost"
	if hostname == "localhost" {
		return true
	}
	return strings.Contains(hostname, ".")
}

// LoginToBase64 encodes a username and password into a base64-encoded string in "username:password" format.
// This is commonly used for HTTP Basic Authentication.
//
// Parameters:
//   - username: string - The username to encode.
//   - password: string - The password to encode.
//
// Returns:
//   - string: The base64-encoded "username:password" string.
func LoginToBase64(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// CheckIfname validates a network interface name according to the following rules:
//   - Must not be empty.
//   - Should not exceed 15 characters (warning if it does).
//   - Should not contain non-ASCII characters (warning if it does).
//   - Should not contain invalid characters: '/', whitespace, or control characters.
//
// Parameters:
//   - name: string - The interface name to validate.
//
// Returns:
//   - error: An error if the name is invalid, or nil if valid.
func CheckIfname(name string) error {
	if name == "" {
		return errors.New("interface name cannot be empty")
	}

	if len(name) >= 16 {
		log.Printf("Warning: interface name '%s' is longer than %d characters", name, 16-1)
	}

	var invalidChar bool
	var hasWhitespace bool

	for _, r := range name {
		if r > 127 {
			invalidChar = true
			break
		}
		if r == '/' || r == ' ' || strings.ContainsRune("\t\n\v\f\r", r) {
			hasWhitespace = true
			break
		}
	}

	if invalidChar {
		log.Printf("Warning: interface name contains non-ASCII character")
	}

	if hasWhitespace {
		return errors.New("interface name contains invalid character: '/' or whitespace")
	}

	return nil
}
