package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// nolint:wrapcheck
func downloadCmd() *cobra.Command {
	return downloadCmdWithAppStore(func() appstore.AppStore { return dependencies.AppStore })
}

//nolint:wrapcheck
func downloadCmdWithAppStore(appStore func() appstore.AppStore) *cobra.Command {
	var (
		acquireLicense    bool
		checkLicense      bool
		noUpdate          bool
		expectedAccount   string
		outputPath        string
		appID             int64
		bundleID          string
		externalVersionID string
		platformValue     string
	)

	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download iOS, iPadOS, tvOS, watchOS, visionOS, and macOS app packages from the App Store",
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
				return errors.New("download account does not match selected profile")
			}
			if checkLicense {
				if appID == 0 {
					return errors.New("checking the license requires an app ID")
				}
				_, err := store.Download(appstore.DownloadInput{
					CheckLicenseOnly: true,
					Context:          cmd.Context(),
					Account:          acc,
					App:              appstore.App{ID: appID},
					Platform:         platform,
					OnStage:          newStageReporter(),
				})
				if err != nil && !errors.Is(err, appstore.ErrLicenseRequired) {
					return err
				}
				dependencies.Logger.Log().Bool("owned", err == nil).Bool("success", true).Send()
				return nil
			}
			var lastErr error
			purchaseRequired := false
			purchased := false
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
						return errors.New("download account does not match selected profile after refreshing sign-in")
					}
					acc = loginResult.Account
					emitRefreshedSession(acc)
				}

				app := appstore.App{ID: appID, BundleID: bundleID}

				if bundleID != "" {
					lookupResult, err := store.Lookup(appstore.LookupInput{
						Account:  acc,
						BundleID: bundleID,
						Platform: platform,
					})
					if err != nil && (appID == 0 || !errors.Is(err, appstore.ErrAppNotFound)) {
						return err
					}

					// Delisted apps may still be downloadable by their numeric ID.
					if err == nil {
						app = lookupResult.App
					}
				}

				if errors.Is(lastErr, appstore.ErrLicenseRequired) {
					purchaseRequired = true
				}

				if purchaseRequired {
					stage("正在获取免费应用许可")
					err := store.Purchase(appstore.PurchaseInput{
						Context:  cmd.Context(),
						Account:  acc,
						App:      app,
						Platform: platform,
					})
					if err != nil && !errors.Is(err, appstore.ErrLicenseAlreadyExists) {
						if refreshed && appstore.IsSessionRefreshRequired(err) {
							return fmt.Errorf("free app license rejected after sign-in refresh: %w", err)
						}
						return err
					}
					purchaseRequired = false
					purchased = true
					dependencies.Logger.Verbose().
						Bool("success", true).
						Msg("purchase")
				}

				var progress *progressbar.ProgressBar
				if interactive {
					progress = progressbar.NewOptions64(1,
						progressbar.OptionSetDescription("downloading"),
						progressbar.OptionSetWriter(os.Stdout),
						progressbar.OptionShowBytes(true),
						progressbar.OptionSetWidth(20),
						progressbar.OptionFullWidth(),
						progressbar.OptionThrottle(65*time.Millisecond),
						progressbar.OptionShowCount(),
						progressbar.OptionClearOnFinish(),
						progressbar.OptionSpinnerType(14),
						progressbar.OptionSetElapsedTime(false),
						progressbar.OptionSetPredictTime(false),
					)
				}

				out, err := store.Download(appstore.DownloadInput{
					OnStage:            stage,
					Context:            cmd.Context(),
					Account:            acc,
					App:                app,
					OutputPath:         outputPath,
					Progress:           progress,
					ExternalVersionID:  externalVersionID,
					Platform:           platform,
					OmitUpdateMetadata: noUpdate,
				})
				if err != nil {
					return err
				}

				if err := replicateDownloadSinf(store, platform, out); err != nil {
					return err
				}

				event := dependencies.Logger.Log().
					Str("output", out.DestinationPath).
					Bool("purchased", purchased).
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
				retry.Attempts(3),
				retry.RetryIf(func(err error) bool {
					lastErr = err

					if appstore.IsSessionRefreshRequired(err) {
						return !refreshed
					}

					if errors.Is(err, appstore.ErrLicenseRequired) && acquireLicense && !purchased {
						return true
					}

					return false
				}),
			)
		},
	}

	cmd.Flags().Int64VarP(&appID, "app-id", "i", 0, "ID of the target app (required)")
	cmd.Flags().StringVarP(&bundleID, "bundle-identifier", "b", "", "The bundle identifier of the target app (overrides the app ID when found)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "The destination path of the downloaded app package")
	cmd.Flags().StringVar(&externalVersionID, "external-version-id", "", "External version identifier of the target app (defaults to latest version when not specified)")
	cmd.Flags().StringVar(&platformValue, "platform", "", "Platform to download for: iphone (iOS), ipad (iPadOS), appletv (tvOS), watchos, visionos, or macos")
	cmd.Flags().StringVar(&expectedAccount, "expected-account", "", "Expected account identity for the selected desktop profile")
	cmd.Flags().BoolVar(&acquireLicense, "purchase", false, "Obtain a license for the app if needed")
	cmd.Flags().BoolVar(&checkLicense, "check-license", false, "Check the account's license without downloading or acquiring the app")
	cmd.Flags().BoolVar(&noUpdate, "no-update", false, "Omit the App Store update metadata from the saved IPA")

	return cmd
}

func isInteractive(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	interactive, _ := ctx.Value(interactiveKey).(bool)
	return interactive
}

func refreshDownloadLogin(ctx context.Context, store appstore.AppStore, account appstore.Account, interactive bool) (appstore.LoginOutput, error) {
	input := appstore.LoginInput{Context: ctx, Email: account.Email, Password: account.Password}
	if input.Password == "" && interactive {
		password, err := readPrompt("enter password: ", true)
		if err != nil {
			return appstore.LoginOutput{}, err
		}
		input.Password = password
	}
	output, err := store.Login(input)
	if !interactive || !canProvideVerificationCode(err) {
		return output, err
	}
	code, err := readVerificationCode(err)
	if err != nil {
		return appstore.LoginOutput{}, err
	}
	input.AuthCode = code
	return store.Login(input)
}

func emitRefreshedSession(acc appstore.Account) {
	if dependencies.Logger == nil {
		return
	}
	dependencies.Logger.Log().
		Str("email", acc.Email).
		Str("storeFront", acc.StoreFront).
		Bool("sessionRefreshed", true).
		Send()
}

func wrapSessionRefreshError(cause, err error) error {
	if canProvideVerificationCode(err) ||
		errors.Is(err, appstore.ErrInvalidCredentials) ||
		errors.Is(err, appstore.ErrVerificationRejected) {
		return fmt.Errorf("failed to refresh Apple login: %w", err)
	}

	return fmt.Errorf("failed to refresh Apple login (%w): %w", cause, err)
}

type sinfReplicator interface {
	ReplicateSinf(input appstore.ReplicateSinfInput) error
}

//nolint:wrapcheck
func replicateDownloadSinf(store sinfReplicator, platform appstore.Platform, out appstore.DownloadOutput) error {
	if out.SinfReplicated || platform == appstore.PlatformMacOS && len(out.Sinfs) == 0 {
		return nil
	}

	return store.ReplicateSinf(appstore.ReplicateSinfInput{Sinfs: out.Sinfs, PackagePath: out.DestinationPath})
}
