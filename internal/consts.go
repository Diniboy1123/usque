package internal

import "time"

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a4471"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "https://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
)

// socks5 server
const (
	DefaultSocksBindAddress       = "0.0.0.0"
	DefaultSocksPort              = "1080"
	DefaultSocksConnectPort       = 443
	DefaultSocksDnsTimeout        = 2 * time.Second  // 2000000000
	DefaultSocksKeepalivePeriod   = 30 * time.Second // 30000000000
	DefaultSocksMTU               = 1280
	DefaultSocksInitialPacketSize = 1242
	DefaultSocksReconnectDelay    = 1 * time.Second //1000000000
)

var Headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}

var DefaultSocksDnsServers = []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}
