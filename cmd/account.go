package cmd

import (
	"log"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage account and license keys",
	Long:  "Manage account information and license key operations for WARP.",
}

var accountInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display current account information",
	Long:  "Display detailed information about the current WARP account.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			log.Fatalln("Config not loaded. Please register first.")
		}

		account, err := api.GetAccount(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			log.Fatalf("Failed to get account: %v\n", err)
		}

		cmd.Println("Account ID:                 ", account.ID)

		if len(account.AccountType) > 0 {
			cmd.Println("Type:                       ", account.AccountType)
		}

		if created, err := time.Parse(time.RFC3339Nano, account.Created); err == nil {
			cmd.Println("Created:                    ", created.Format(time.DateTime))
		}

		if updated, err := time.Parse(time.RFC3339Nano, account.Updated); err == nil {
			cmd.Println("Updated:                    ", updated.Format(time.DateTime))
		}

		if managed, err := time.Parse(time.RFC3339Nano, account.Managed); err == nil {
			cmd.Println("Managed:                    ", managed.Format(time.DateTime))
		}

		if len(account.Organization) > 0 {
			cmd.Println("Organization:               ", account.Organization)
		}

		if len(account.Role) > 0 {
			cmd.Println("Role:                       ", account.Role)
		}

		if len(account.License) > 0 {
			cmd.Println("Licence Key:                ", account.License)
		}

		if account.PremiumData > 0 {
			cmd.Println("Premium Data:               ", account.PremiumData)
		}

		if account.Quota > 0 {
			cmd.Println("Quota:                      ", account.Quota)
		}

		if account.ReferralCount > 0 {
			cmd.Println("Referral Count: ", account.ReferralCount)
		}

		if account.ReferralRenewalCount > 0 {
			cmd.Println("Referral Renewal Countdown: ", account.ReferralRenewalCount)
		}
	},
}

var accountDevicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "List connected devices",
	Long:  "Display information about devices connected with the current WARP account.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			log.Fatalln("Config not loaded. Please register first.")
		}

		devices, err := api.GetDevices(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			log.Fatalf("Failed to get devices: %v\n", err)
			return
		}

		for index, account := range *devices {
			cmd.Printf("Device #%d:\n", index+1)
			cmd.Println("  ID:         ", account.ID)

			if len(account.Type) > 0 {
				cmd.Println("  Type:       ", account.Type)
			}

			if len(account.Model) > 0 {
				cmd.Println("  Model:      ", account.Model)
			}

			if len(account.Name) > 0 {
				cmd.Println("  Name:       ", account.Name)
			}

			if created, err := time.Parse(time.RFC3339Nano, account.Created); err == nil {
				cmd.Println("  Created:    ", created.Format(time.DateTime))
			}

			if activated, err := time.Parse(time.RFC3339Nano, account.Activated); err == nil {
				cmd.Println("  Activated:  ", activated.Format(time.DateTime))
			}

			cmd.Println("  Active:     ", account.Active)

			if len(account.Role) > 0 {
				cmd.Println("  Role:       ", account.Role)
			}
		}
	},
}

var accountSetCmd = &cobra.Command{
	Use:   "set <LICENSE-KEY>",
	Short: "Set WARP license key",
	Long: "Bind the current device to a WARP account by setting a license key.\n" +
		"The license key must have the following format: 'xxxxxxxx-xxxxxxxx-xxxxxxxx'.",
	Args:       cobra.MinimumNArgs(1),
	ArgAliases: []string{"licence-key"},
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			log.Fatalln("Config not loaded. Please register first.")
			return
		}

		if len(args) < 1 {
			log.Fatalln("required license-key argument")
			return
		}

		licenceKey := args[0]

		err := api.UpdateLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken, licenceKey)
		if err != nil {
			log.Fatalf("Failed to set licence key: %v\n", err)
		}

		log.Println("Licence key successfully changed")
	},
}

var accountResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove WARP license key",
	Long: "Unbind the current device from the WARP account by removing the license key.\n" +
		"This will free up the license key to be used on another device.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			log.Fatalln("Config not loaded. Please register first.")
		}

		err := api.DeleteLicenceKey(config.AppConfig.ID, config.AppConfig.AccessToken)
		if err != nil {
			log.Fatalf("Failed to reset licence key: %v\n", err)
		}

		log.Println("Licence key successfully removed")
	},
}

func init() {
	accountCmd.AddCommand(accountInfoCmd)
	accountCmd.AddCommand(accountSetCmd)
	accountCmd.AddCommand(accountResetCmd)
	accountCmd.AddCommand(accountDevicesCmd)
	rootCmd.AddCommand(accountCmd)
}
