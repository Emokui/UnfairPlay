package cmd

import (
	"errors"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

// nolint:wrapcheck
func ListVersionsCmd() *cobra.Command {
	var (
		appID         int64
		bundleID      string
		platformValue string
	)

	cmd := &cobra.Command{
		Use:   "list-versions",
		Short: "List the available versions of an App Store app",
		RunE: func(cmd *cobra.Command, args []string) error {
			if appID == 0 && bundleID == "" {
				return errors.New("either the app ID or the bundle identifier must be specified")
			}

			platform, err := appstore.ParsePlatform(platformValue)
			if err != nil {
				return err
			}

			store := dependencies.AppStore
			infoResult, err := store.AccountInfo()
			if err != nil {
				return err
			}

			acc := infoResult.Account
			var lastErr error
			refreshed := false
			interactive := isInteractive(cmd.Context())
			stage := newStageReporter()

			return retry.Do(func() error {
				if appstore.IsSessionRefreshRequired(lastErr) {
					refreshed = true
					stage("正在更新 Apple 登录会话")
					loginResult, err := refreshDownloadLogin(cmd.Context(), store, acc, interactive)
					if err != nil {
						return wrapSessionRefreshError(lastErr, err)
					}

					acc = loginResult.Account
					emitRefreshedSession(acc)
				}

				app := appstore.App{ID: appID}
				if bundleID != "" {
					lookupResult, err := store.Lookup(appstore.LookupInput{Account: acc, BundleID: bundleID, Platform: platform})
					if err != nil {
						return err
					}

					app = lookupResult.App
				}

				out, err := store.ListVersions(appstore.ListVersionsInput{Context: cmd.Context(), Account: acc, App: app, Platform: platform})
				if err != nil {
					return err
				}

				event := dependencies.Logger.Log().
					Interface("externalVersionIdentifiers", out.ExternalVersionIdentifiers).
					Str("bundleID", app.BundleID).
					Bool("success", true)
				if refreshed {
					event = event.Str("email", acc.Email).Str("storeFront", acc.StoreFront)
				}
				event.Send()

				return nil
			},
				retry.LastErrorOnly(true),
				retry.DelayType(retry.FixedDelay),
				retry.Delay(time.Millisecond),
				retry.Attempts(2),
				retry.RetryIf(func(err error) bool {
					lastErr = err

					return !refreshed && appstore.IsSessionRefreshRequired(err)
				}),
			)
		},
	}

	cmd.Flags().Int64VarP(&appID, "app-id", "i", 0, "ID of the target app (required)")
	cmd.Flags().StringVarP(&bundleID, "bundle-identifier", "b", "", "The bundle identifier of the target app (overrides the app ID)")

	cmd.Flags().StringVar(&platformValue, "platform", "", "Platform to list versions for: iphone (iOS), ipad (iPadOS), appletv (tvOS), watchos, visionos, or macos")

	return cmd
}
