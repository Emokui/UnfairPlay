package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

// nolint:wrapcheck
func getVersionMetadataCmd() *cobra.Command {
	return getVersionMetadataCmdWithAppStore(func() appstore.AppStore { return dependencies.AppStore })
}

// nolint:wrapcheck
func getVersionMetadataCmdWithAppStore(appStore func() appstore.AppStore) *cobra.Command {
	var (
		appID             int64
		bundleID          string
		expectedAccount   string
		externalVersionID string
		platformValue     string
	)

	cmd := &cobra.Command{
		Use:   "get-version-metadata",
		Short: "Retrieves the metadata for a specific version of an app",
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
			if expectedAccount != "" && !strings.EqualFold(strings.TrimSpace(expectedAccount), strings.TrimSpace(acc.Email)) {
				return errors.New("version metadata account does not match selected profile")
			}
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
					if expectedAccount != "" && !strings.EqualFold(strings.TrimSpace(expectedAccount), strings.TrimSpace(loginResult.Account.Email)) {
						return errors.New("version metadata account does not match selected profile after refreshing sign-in")
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

				out, err := store.GetVersionMetadata(appstore.GetVersionMetadataInput{
					Context:   cmd.Context(),
					Account:   acc,
					App:       app,
					VersionID: externalVersionID,
					Platform:  platform,
				})
				if err != nil {
					return err
				}

				event := dependencies.Logger.Log().
					Str("externalVersionID", externalVersionID).
					Str("displayVersion", out.DisplayVersion).
					Time("releaseDate", out.ReleaseDate).
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
	cmd.Flags().StringVar(&externalVersionID, "external-version-id", "", "External version identifier of the target app (required)")

	cmd.Flags().StringVar(&platformValue, "platform", "", "Platform to retrieve metadata for: iphone (iOS), ipad (iPadOS), appletv (tvOS), watchos, visionos, or macos")
	cmd.Flags().StringVar(&expectedAccount, "expected-account", "", "Expected account identity for the selected desktop profile")

	_ = cmd.MarkFlagRequired("external-version-id")

	return cmd
}
