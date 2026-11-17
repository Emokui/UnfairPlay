package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the App Store",
	}

	cmd.AddCommand(loginCmd())
	cmd.AddCommand(infoCmd())
	cmd.AddCommand(revokeCmd())

	return cmd
}

func loginCmd() *cobra.Command {
	var email, password, authCode string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the App Store",
		RunE: func(cmd *cobra.Command, args []string) error {
			interactive := cmd.Context().Value(interactiveKey).(bool)

			if email == "" && !interactive {
				return errors.New("an Apple ID is required when not running in interactive mode; use the \"--email\" flag")
			}

			if email == "" && interactive {
				value, err := readPrompt("enter Apple ID (email address or phone number): ", false)
				if err != nil {
					return fmt.Errorf("failed to read Apple ID: %w", err)
				}
				email = value
			}

			if password == "" && !interactive {
				return errors.New("password is required when not running in interactive mode; use the \"--password\" flag")
			}

			if password == "" && interactive {
				value, err := readPrompt("enter password: ", true)
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = value
			}

			dependencies.Logger.Log().Msg("正在准备本地认证；首次需要更新组件，完成后自动复用缓存")

			var lastErr error

			// nolint:wrapcheck
			return retry.Do(func() error {
				if interactive && canProvideVerificationCode(lastErr) {
					var err error
					authCode, err = readVerificationCode(lastErr)
					if err != nil {
						return fmt.Errorf("failed to read auth code: %w", err)
					}
				}

				dependencies.Logger.Verbose().
					Str("email", email).
					Bool("authCodeProvided", authCode != "").
					Msg("logging in")

				output, err := dependencies.AppStore.Login(appstore.LoginInput{
					Context:  cmd.Context(),
					Email:    email,
					Password: password,
					AuthCode: authCode,
				})
				if err != nil {
					if errors.Is(err, appstore.ErrAuthCodeRequired) && !interactive {
						dependencies.Logger.Log().Msg("2FA code is required; run the command again and supply a code using the `--auth-code` flag")

						return nil
					}

					return err
				}

				dependencies.Logger.Log().
					Str("name", output.Account.Name).
					Str("email", output.Account.Email).
					Str("storeFront", output.Account.StoreFront).
					Bool("success", true).
					Send()

				return nil
			},
				retry.LastErrorOnly(true),
				retry.DelayType(retry.FixedDelay),
				retry.Delay(time.Millisecond),
				retry.Attempts(2),
				retry.RetryIf(func(err error) bool {
					lastErr = err

					return interactive && authCode == "" && canProvideVerificationCode(err)
				}),
			)
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Apple ID email address or phone number (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password for the Apple ID (required)")
	cmd.Flags().StringVar(&authCode, "auth-code", "", "2FA code for the Apple ID")

	return cmd
}

func canProvideVerificationCode(err error) bool {
	return errors.Is(err, appstore.ErrAuthCodeRequired) || errors.Is(err, appstore.ErrAuthenticationAmbiguous)
}

func readVerificationCode(loginErr error) (string, error) {
	prompt := "enter 2FA code: "
	if errors.Is(loginErr, appstore.ErrAuthenticationAmbiguous) {
		prompt = "Apple could not confirm sign-in. If you received a code, enter it or leave blank: "
	}
	code, err := readPrompt(prompt, false)
	if err == nil && strings.TrimSpace(code) == "" {
		return "", loginErr
	}
	return code, err
}

// nolint:wrapcheck
func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show current account info",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := dependencies.AppStore.AccountInfo()
			if err != nil {
				return err
			}

			dependencies.Logger.Log().
				Str("name", output.Account.Name).
				Str("email", output.Account.Email).
				Str("storeFront", output.Account.StoreFront).
				Bool("success", true).
				Send()

			return nil
		},
	}
}

// nolint:wrapcheck
func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke",
		Short: "Revoke your App Store credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := dependencies.AppStore.Revoke()
			if err != nil {
				return err
			}

			dependencies.Logger.Log().Bool("success", true).Send()

			return nil
		},
	}
}
