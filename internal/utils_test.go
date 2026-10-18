package internal

import "testing"

func TestParsePortMappingProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mapping string
		network string
	}{
		{name: "tcp by default", mapping: "localhost:5353:100.96.0.2:53", network: "tcp"},
		{name: "explicit tcp", mapping: "localhost:5353:100.96.0.2:53/tcp", network: "tcp"},
		{name: "udp", mapping: "127.0.0.1:5353:1.1.1.1:53/udp", network: "udp"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			mapping, err := ParsePortMapping(test.mapping)
			if err != nil {
				t.Fatalf("ParsePortMapping(%q) failed: %v", test.mapping, err)
			}
			if mapping.Network != test.network {
				t.Errorf("network = %q, want %q", mapping.Network, test.network)
			}
			if mapping.LocalPort != 5353 {
				t.Errorf("local port = %d, want 5353", mapping.LocalPort)
			}
			if mapping.RemotePort != 53 {
				t.Errorf("remote port = %d, want 53", mapping.RemotePort)
			}
		})
	}
}

func TestParsePortMappingUDPKeepsAddresses(t *testing.T) {
	t.Parallel()

	mapping, err := ParsePortMapping("0.0.0.0:51820:100.96.0.2:51820/udp")
	if err != nil {
		t.Fatalf("ParsePortMapping failed: %v", err)
	}

	if mapping.Network != "udp" {
		t.Errorf("network = %q, want udp", mapping.Network)
	}
	if mapping.BindAddress != "0.0.0.0" {
		t.Errorf("bind address = %q, want 0.0.0.0", mapping.BindAddress)
	}
	if mapping.RemoteIP != "100.96.0.2" {
		t.Errorf("remote IP = %q, want 100.96.0.2", mapping.RemoteIP)
	}
}

func TestParsePortMappingRejectsInvalidUDPMapping(t *testing.T) {
	t.Parallel()

	if _, err := ParsePortMapping("not-a-mapping/udp"); err == nil {
		t.Fatal("ParsePortMapping accepted an invalid UDP mapping")
	}
}
