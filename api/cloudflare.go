package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// Register creates a new user account by registering a WireGuard public key and generating a random Android-like device identifier.
// The WireGuard private key isn't stored anywhere, therefore it won't be usable. It's sole purpose is to mimic the Android app's registration process.
//
// This function sends a POST request to the API to register a new user and returns the created account data.
//
// Parameters:
//   - model: string - The device model string to register. (e.g., "PC")
//   - locale: string - The user's locale. (e.g., "en-US")
//   - jwt: string - Team token to register.
//   - acceptTos: bool - Whether the user accepts the Terms of Service (TOS). If false, the user will be prompted to accept.
//
// Returns:
//   - models.AccountData: The account data returned from the registration process.
//   - error:              An error if registration fails at any step.
//
// Example:
//
//	account, err := Register("PC", "en-US", "", false)
//	if err != nil {
//	    log.Fatalf("Registration failed: %v", err)
//	}
func Register(model, locale, jwt string, acceptTos bool) (*models.AccountData, error) {
	wgKey, err := internal.GenerateRandomWgPubkey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate wg key: %v", err)
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %v", err)
	}

	if !acceptTos {
		fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return nil, fmt.Errorf("failed to read user input: %v", err)
		}
		if response != "y" {
			return nil, fmt.Errorf("user did not accept TOS")
		}
	}

	data := models.Registration{
		Key:       wgKey,
		InstallID: "",
		FcmToken:  "",
		Tos:       internal.TimeAsCfString(time.Now()),
		Model:     model,
		Serial:    serial,
		OsVersion: "",
		KeyType:   internal.KeyTypeWg,
		TunType:   internal.TunTypeWg,
		Locale:    locale,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("POST", internal.ApiUrl+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, &apiErr
	}

	var accountData models.AccountData
	if err := json.Unmarshal(body, &accountData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &accountData, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key.
//
// This function sends a PATCH request to update the user's account with a new key.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//   - pubKey: []byte - The new MASQUE public key in binary format
//   - deviceName: string - The name of the device to enroll (optional)
//
// Returns:
//   - *models.AccountData: The updated account data after key enrollment
//   - error:              An error if the enrollment process fails
//
// Example:
//
//	updatedAccount, err := EnrollKey(deviceId, accessToken, pubKey, "MyPC")
//	if err != nil {
//	    log.Fatalf("Key enrollment failed: %v", err)
//	}
func EnrollKey(deviceId string, deviceToken string, pubKey []byte, deviceName string) (*models.AccountData, error) {
	deviceUpdate := models.DeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
	}

	if deviceName != "" {
		deviceUpdate.Name = deviceName
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("PATCH", internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, &apiErr
	}

	var accountData models.AccountData
	if err := json.Unmarshal(body, &accountData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &accountData, nil
}

// GetAccount retrieves the account information associated with the device.
//
// This function sends a GET request to retrieve account details including license key status,
// account type, and other account-related information.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - *models.Account: The account information including license key and account status
//   - error:           An error if the request fails or account is not found
func GetAccount(deviceId string, deviceToken string) (*models.Account, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, &apiErr
	}

	var respData models.Account
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &respData, nil
}

// UpdateLicenceKey updates the license key associated with a device.
//
// This function sends a PUT request to bind a new license key to the current device.
// The device will be associated with the WARP account linked to the provided license key.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//   - licenceKey: string - The new license key to bind to the device
//
// Returns:
//   - error: An error if the update fails or the license key is invalid
func UpdateLicenceKey(deviceId string, deviceToken string, licenceKey string) error {
	deviceUpdate := models.Account{
		License: licenceKey,
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return fmt.Errorf("failed to parse error response: %v", err)
		}
		return &apiErr
	}

	return nil
}

// DeleteLicenceKey removes the license key associated with the device.
//
// This function sends a DELETE request to unbind the license key from the current device.
// After removal, the device will no longer have WARP connectivity and the license key
// can be used on a different device.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - error: An error if the removal fails
func DeleteLicenceKey(deviceId string, deviceToken string) error {
	req, err := http.NewRequest(http.MethodDelete, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return fmt.Errorf("failed to parse error response: %v", err)
		}
		return &apiErr
	}

	return nil
}

// GetDevices retrieves a list of all devices associated with the same license key.
//
// This function sends a GET request to retrieve information about all devices that share
// the same license key binding as the current device.
//
// Parameters:
//   - deviceId: string - The device registration ID
//   - deviceToken: string - The device registration access token
//
// Returns:
//   - *models.Devices: A list of devices associated with the license key
//   - error:           An error if the request fails
func GetDevices(deviceId string, deviceToken string) (*models.Devices, error) {
	req, err := http.NewRequest(http.MethodGet, internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+deviceId+"/account/devices", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+deviceToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return nil, &apiErr
	}

	var respData models.Devices
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &respData, nil
}
