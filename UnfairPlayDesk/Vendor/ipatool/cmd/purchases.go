package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

// nolint:wrapcheck
func listPurchasesCmd() *cobra.Command {
	var page, maxResults int

	var platformValue string

	var platform appstore.Platform

	cmd := &cobra.Command{
		Use:   "list-purchases",
		Short: "List apps owned by the authenticated App Store account",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if page < 1 {
				return errors.New("page must be greater than 0")
			}
			if maxResults < 1 {
				return errors.New("max results must be greater than 0")
			}
			if maxResults > appstore.MaxOwnedAppsLimit {
				return fmt.Errorf("max results must not exceed %d", appstore.MaxOwnedAppsLimit)
			}

			var err error
			platform, err = appstore.ParsePlatform(platformValue)

			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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

				output, err := store.OwnedApps(appstore.OwnedAppsInput{
					Account:  acc,
					Page:     page,
					Limit:    maxResults,
					Platform: platform,
				})
				if err != nil {
					return err
				}

				dependencies.Logger.Log().
					Int("count", output.Count).
					Int("totalCount", output.TotalCount).
					Int("page", output.Page).
					Array("apps", appstore.Apps(output.Results)).
					Send()

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

	cmd.Flags().IntVarP(&maxResults, "max-results", "l", appstore.DefaultOwnedAppsLimit, "maximum number of apps to return per page")
	cmd.Flags().IntVarP(&page, "page", "p", 1, "page of owned apps to return")
	cmd.Flags().StringVar(&platformValue, "platform", "", "Filter by platform: iphone (iOS), ipad (iPadOS), appletv (tvOS), visionos, or macos")

	return cmd
}
