package models

type Registration struct {
	Key       string `json:"key"`
	InstallID string `json:"install_id"`
	FcmToken  string `json:"fcm_token"`
	Tos       string `json:"tos"`
	Model     string `json:"model"`
	Serial    string `json:"serial_number"`
	OsVersion string `json:"os_version"`
	KeyType   string `json:"key_type"`
	TunType   string `json:"tunnel_type"`
	Locale    string `json:"locale"`
}

type AccountData struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"`
	Model   string  `json:"model"`
	Name    string  `json:"name"`
	Key     string  `json:"key"`
	KeyType string  `json:"key_type"`
	TunType string  `json:"tunnel_type"`
	Account Account `json:"account"`
	Config  Config  `json:"config"`
	// WarpEnabled not set for ZeroTier
	WarpEnabled bool `json:"warp_enabled,omitempty"`
	// Waitlist not set for ZeroTier
	Waitlist bool   `json:"waitlist_enabled,omitempty"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
	// Tos not set for ZeroTier
	Tos string `json:"tos,omitempty"`
	// Place not set for ZeroTier
	Place  int    `json:"place,omitempty"`
	Locale string `json:"locale"`
	// Enabled not set for ZeroTier
	Enabled   bool   `json:"enabled,omitempty"`
	InstallID string `json:"install_id"`
	// Token only set for /reg call
	Token    string `json:"token,omitempty"`
	FcmToken string `json:"fcm_token"`
	// SerialNumber not set for ZeroTier
	SerialNumber string `json:"serial_number,omitempty"`
	Policy       Policy `json:"policy"`
}

type Account struct {
	ID          string `json:"id"`
	AccountType string `json:"account_type,omitempty"`
	// Created not set for ZeroTier
	Created string `json:"created,omitempty"`
	// Updated not set for ZeroTier
	Updated string `json:"updated,omitempty"`
	// Managed only set for ZeroTier
	Managed string `json:"managed,omitempty"`
	// Organization only set for ZeroTier
	Organization string `json:"organization,omitempty"`
	// PremiumData not set for ZeroTier
	PremiumData int `json:"premium_data,omitempty"`
	// Quota not set for ZeroTier
	Quota int `json:"quota,omitempty"`
	// WarpPlus not set for ZeroTier
	WarpPlus bool `json:"warp_plus,omitempty"`
	// ReferralCode not set for ZeroTier
	ReferralCount int `json:"referral_count,omitempty"`
	// ReferralRenewalCount not set for ZeroTier
	ReferralRenewalCount int `json:"referral_renewal_countdown,omitempty"`
	// Role not set for ZeroTier
	Role string `json:"role,omitempty"`
	// License not set for ZeroTier
	License string `json:"license,omitempty"`
}

type Config struct {
	ClientID  string `json:"client_id"`
	Peers     []Peer `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
	} `json:"interface"`
	Services struct {
		HTTPProxy string `json:"http_proxy"`
	} `json:"services"`
}

type Peer struct {
	PublicKey string `json:"public_key"`
	Endpoint  struct {
		V4    string `json:"v4"`
		V6    string `json:"v6"`
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	} `json:"endpoint"`
}

type Policy struct {
	TunnelProtocol string `json:"tunnel_protocol"`
	// TODO: add ZeroTier fields
}

type Devices []Device

type Device struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Model     string `json:"model"`
	Name      string `json:"name,omitempty"`
	Created   string `json:"created"`
	Activated string `json:"activated"`
	Active    bool   `json:"active"`
	Role      string `json:"role"`
}
