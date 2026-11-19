package cmd

import (
	"errors"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

// nolint:wrapcheck
func purchaseCmd() *cobra.Command {
	return purchaseCmdWithAppStore(func() appstore.AppStore { return dependencies.AppStore })
}

//nolint:wrapcheck
func purchaseCmdWithAppStore(appStore func() appstore.AppStore) *cobra.Command {
	var (
		appID         int64
		bundleID      string
		platformValue string
	)

	cmd := &cobra.Command{
		Use:   "purchase",
		Short: "Obtain a license for the app from the App Store",
		RunE: func(cmd *cobra.Command, args []string) error {
			if appID == 0 && bundleID == "" {
				return errors.New("either the app ID or the bundle identifier must be specified")
			}

			platform, err := appstore.ParsePlatform(platformValue)
			if err != nil {
				return err
			}

			store := appStore()
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
					lookupResult, err := store.Lookup(appstore.LookupInput{
						Account:  acc,
						BundleID: bundleID,
						Platform: platform,
					})
					if err != nil {
						return err
					}

					app = lookupResult.App
				}

				err = store.Purchase(appstore.PurchaseInput{
					Context:  cmd.Context(),
					Account:  acc,
					App:      app,
					Platform: platform,
				})
				if err != nil && !errors.Is(err, appstore.ErrLicenseAlreadyExists) {
					return err
				}

				event := dependencies.Logger.Log().
					Bool("alreadyOwned", errors.Is(err, appstore.ErrLicenseAlreadyExists)).
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

	cmd.Flags().Int64VarP(&appID, "app-id", "i", 0, "ID of the target app")
	cmd.Flags().StringVarP(&bundleID, "bundle-identifier", "b", "", "The bundle identifier of the target app (overrides the app ID)")
	cmd.Flags().StringVar(&platformValue, "platform", "", "Platform to purchase for: iphone (iOS), ipad (iPadOS), appletv (tvOS), watchos, visionos, or macos")

	return cmd
}
