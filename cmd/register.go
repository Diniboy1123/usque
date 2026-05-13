package cmd

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new client and enroll a device key",
	Long: "Registers a new account and enrolls a device key. Also makes sure that it switches to" +
		" MASQUE mode. Saves the config to a file.",
	Run: func(cmd *cobra.Command, args []string) {
		if config.ConfigLoaded {
			fmt.Printf("You already have a config. Do you want to overwrite it? (y/n) ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				log.Fatalf("Failed to read response: %v", err)
			}
			if response != "y" {
				return
			}
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		deviceName, err := cmd.Flags().GetString("name")
		if err != nil {
			log.Fatalf("Failed to get device name: %v", err)
		}

		locale, err := cmd.Flags().GetString("locale")
		if err != nil {
			log.Fatalf("Failed to get locale: %v", err)
		}

		model, err := cmd.Flags().GetString("model")
		if err != nil {
			log.Fatalf("Failed to get model: %v", err)
		}

		jwt, err := cmd.Flags().GetString("jwt")
		if err != nil {
			log.Fatalf("Failed to get jwt: %v", err)
		}

		if jwt != "" {
			log.Printf("Registering with locale %s and model %s using jwt authentication", locale, model)
		} else {
			log.Printf("Registering with locale %s and model %s", locale, model)
		}

		acceptTos, err := cmd.Flags().GetBool("accept-tos")
		if err != nil {
			log.Fatalf("Failed to get accept-tos flag: %v", err)
		}

		accountData, err := api.Register(model, locale, jwt, acceptTos)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}

		privKey, pubKey, err := internal.GenerateEcKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		log.Printf("Enrolling device key...")

		updatedAccountData, err := api.EnrollKey(accountData.ID, accountData.Token, pubKey, deviceName)
		if err != nil {
			log.Fatalf("Failed to enroll key: %v", err)
		}

		log.Printf("Successful registration. Saving config...")

		config.AppConfig = config.Config{
			PrivateKey: base64.StdEncoding.EncodeToString(privKey),
			// TODO: proper endpoint parsing in utils
			// strip :0
			EndpointV4: updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
			// strip [ from beginning and ]:0 from end
			EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
			EndpointH2V4:   config.DefaultEndpointH2V4,
			EndpointH2V6:   config.DefaultEndpointH2V6,
			EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
			ID:             updatedAccountData.ID,
			AccessToken:    accountData.Token,
			IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
			IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
		}

		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		log.Printf("Config saved to %s", configPath)
	},
}

func init() {
	registerCmd.Flags().StringP("locale", "l", internal.DefaultLocale, "locale")
	registerCmd.Flags().StringP("model", "m", internal.DefaultModel, "model")
	registerCmd.Flags().StringP("name", "n", "", "device name")
	registerCmd.Flags().String("jwt", "", "team token")
	registerCmd.Flags().BoolP("accept-tos", "a", false, "accept Cloudflare TOS (not interactive setup)")
	rootCmd.AddCommand(registerCmd)
}
