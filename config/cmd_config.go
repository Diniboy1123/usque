package config

import (
	"time"
)

type GeneralConfig struct {
	CloudflareConfig  *CloudflareConfig  `json:"cloudflareConfig"`
	NetConfig         *NetConfig         `json:"netConfig"`
	SocksServerConfig *SocksServerConfig `json:"socksServerConfig"`
	HTTPProxyConfig   *HTTPProxyConfig   `json:"httpProxyConfig"`
	NativeTunConfig   *NativeTunConfig   `json:"nativeTunConfig"`
	PortForwardConfig *PortForwardConfig `json:"portForwardConfig"`
	EnrollConfig      *EnrollConfig      `json:"enrollConfig"`
	RegisterConfig    *RegisterConfig    `json:"registerConfig"`
}

// NetConfig represents common network configuration
type NetConfig struct {
	ConnectPort       int           `json:"connectPort" cmd:"connect-port" shorthand:"P"`
	IPv6              bool          `json:"ipv6" cmd:"ipv6" shorthand:"6"`
	NoTunnelIPv4      bool          `json:"noTunnelIPv4" cmd:"no-tunnel-ipv4" shorthand:"F"`
	NoTunnelIPv6      bool          `json:"noTunnelIPv6" cmd:"no-tunnel-ipv6" shorthand:"S"`
	SNIAddress        string        `json:"sniAddress" cmd:"sni-address" shorthand:"s"`
	KeepalivePeriod   time.Duration `json:"keepalivePeriod" cmd:"keepalive-period" shorthand:"k"`
	MTU               int           `json:"mtu" cmd:"mtu" shorthand:"m"`
	InitialPacketSize uint16        `json:"initialPacketSize" cmd:"initial-packet-size" shorthand:"i"`
	ReconnectDelay    time.Duration `json:"reconnectDelay" cmd:"reconnect-delay" shorthand:"r"`
}

type CloudflareConfig struct {
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string `json:"license"`          // Application license key
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address
}

// SocksServerConfig represents configuration for the SOCKS proxy server
type SocksServerConfig struct {
	NetConfig
	BindAddress string        `json:"bindAddress" cmd:"bind" shorthand:"b"`
	Port        string        `json:"port" cmd:"port" shorthand:"p"`
	Username    string        `json:"username" cmd:"username" shorthand:"u"`
	Password    string        `json:"password" cmd:"password" shorthand:"w"`
	DNSServers  []string      `json:"dnsServers" cmd:"dns" shorthand:"d"`
	DNSTimeout  time.Duration `json:"dnsTimeout" cmd:"dns-timeout"`
}

// HTTPProxyConfig represents configuration for the HTTP proxy server
type HTTPProxyConfig struct {
	NetConfig
	BindAddress string   `json:"bindAddress" cmd:"bind" shorthand:"b"`
	Port        string   `json:"port" cmd:"port" shorthand:"p"`
	Username    string   `json:"username" cmd:"username" shorthand:"u"`
	Password    string   `json:"password" cmd:"password" shorthand:"w"`
	DNSServers  []string `json:"dnsServers" cmd:"dns" shorthand:"d"`
}

// NativeTunConfig represents configuration for the native TUN device
type NativeTunConfig struct {
	NetConfig
	NoIproute2 bool `json:"noIproute2" cmd:"no-iproute2" shorthand:"I"`
}

// PortForwardConfig represents configuration for port forwarding
type PortForwardConfig struct {
	NetConfig
	LocalPorts  []string `json:"localPorts" cmd:"local-ports" shorthand:"L"`
	RemotePorts []string `json:"remotePorts" cmd:"remote-ports" shorthand:"R"`
	DNSServers  []string `json:"dnsServers" cmd:"dns" shorthand:"d"`
}

// EnrollConfig represents configuration for device enrollment
type EnrollConfig struct {
	Name     string `json:"name" cmd:"name" shorthand:"n"`
	RegenKey bool   `json:"regenKey" cmd:"regen-key" shorthand:"r"`
}

// RegisterConfig represents configuration for device registration
type RegisterConfig struct {
	Name      string `json:"name" cmd:"name" shorthand:"n"`
	Locale    string `json:"locale" cmd:"locale" shorthand:"l"`
	Model     string `json:"model" cmd:"model" shorthand:"m"`
	JWT       string `json:"jwt" cmd:"jwt"`
	AcceptTos bool   `json:"acceptTos" cmd:"accept-tos" shorthand:"a"`
}

// Create new config instances with default values
func newSocksServerConfig() *SocksServerConfig {
	return &SocksServerConfig{
		NetConfig: NetConfig{
			ConnectPort:       443,
			KeepalivePeriod:   30 * time.Second,
			MTU:               1280,
			InitialPacketSize: 1242,
			ReconnectDelay:    time.Second,
		},
		BindAddress: "0.0.0.0",
		Port:        "1080",
		DNSServers:  []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
	}
}

func newHTTPProxyConfig() *HTTPProxyConfig {
	return &HTTPProxyConfig{
		NetConfig: NetConfig{
			ConnectPort:       443,
			KeepalivePeriod:   30 * time.Second,
			MTU:               1280,
			InitialPacketSize: 1242,
			ReconnectDelay:    time.Second,
		},
		BindAddress: "0.0.0.0",
		Port:        "8000",
		DNSServers:  []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
	}
}

func newNativeTunConfig() *NativeTunConfig {
	return &NativeTunConfig{
		NetConfig: NetConfig{
			ConnectPort:       443,
			KeepalivePeriod:   30 * time.Second,
			MTU:               1280,
			InitialPacketSize: 1242,
			ReconnectDelay:    time.Second,
		},
		NoIproute2: false,
	}
}

func newPortForwardConfig() *PortForwardConfig {
	return &PortForwardConfig{
		NetConfig: NetConfig{
			ConnectPort:       443,
			KeepalivePeriod:   30 * time.Second,
			MTU:               1280,
			InitialPacketSize: 1242,
			ReconnectDelay:    time.Second,
		},
		DNSServers: []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
	}
}

func newEnrollConfig() *EnrollConfig {
	return &EnrollConfig{
		RegenKey: false,
	}
}

func newRegisterConfig() *RegisterConfig {
	return &RegisterConfig{
		AcceptTos: false,
	}
}
