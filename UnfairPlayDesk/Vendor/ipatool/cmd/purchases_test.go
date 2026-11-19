package cmd

import (
	"bytes"
	"context"
	"fmt"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("List Purchases command", func() {
	DescribeTable("passes the platform filter to owned apps",
		func(value string, expected appstore.Platform) {
			store := &fakePurchasesAppStore{}
			previousDependencies := dependencies
			DeferCleanup(func() { dependencies = previousDependencies })
			dependencies.AppStore = store
			dependencies.Logger = log.NewLogger(log.Args{})
			cmd := listPurchasesCmd()
			cmd.SetArgs([]string{"--platform", value})

			Expect(cmd.Execute()).To(Succeed())
			Expect(store.input.Platform).To(Equal(expected))
		},
		Entry("all platforms by default", "", appstore.Platform("")),
		Entry("iOS alias", "ios", appstore.PlatformIPhone),
		Entry("iPadOS alias", "ipados", appstore.PlatformIPad),
		Entry("tvOS alias", "tvos", appstore.PlatformAppleTV),
		Entry("visionOS", "visionos", appstore.PlatformVisionOS),
		Entry("macOS", "macos", appstore.PlatformMacOS),
	)

	DescribeTable("rejects an invalid platform before accessing the account", func(value string) {
		cmd := listPurchasesCmd()
		Expect(cmd.Flags().Set("platform", value)).To(Succeed())
		Expect(cmd.PreRunE(cmd, nil)).To(MatchError(ContainSubstring("invalid platform")))
	},
		Entry("invalid value", "invalid"),
		Entry("unknown is output only", "unknown"),
		Entry("uppercase unknown", "UNKNOWN"),
	)

	It("uses the pagination defaults", func() {
		cmd := listPurchasesCmd()

		page, err := cmd.Flags().GetInt("page")
		Expect(err).ToNot(HaveOccurred())
		Expect(page).To(Equal(1))

		maxResults, err := cmd.Flags().GetInt("max-results")
		Expect(err).ToNot(HaveOccurred())
		Expect(maxResults).To(Equal(appstore.DefaultOwnedAppsLimit))
	})

	DescribeTable("rejects invalid pagination",
		func(flag, value, errorText string) {
			cmd := listPurchasesCmd()
			Expect(cmd.Flags().Set(flag, value)).To(Succeed())

			err := cmd.PreRunE(cmd, nil)
			Expect(err).To(MatchError(ContainSubstring(errorText)))
		},
		Entry("page below one", "page", "0", "page"),
		Entry("max results below one", "max-results", "0", "max results"),
		Entry("max results over limit", "max-results", "101", "100"),
	)

	It("is registered on the root command", func() {
		cmd, _, err := rootCmd().Find([]string{"list-purchases"})

		Expect(err).ToNot(HaveOccurred())
		Expect(cmd.Name()).To(Equal("list-purchases"))
	})

	DescribeTable("refreshes sign-in once with command context and emits refreshed storefront", func(initialErr error) {
		var buf bytes.Buffer
		store := &fakePurchasesAppStore{
			account:      appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143441"},
			loginAccount: appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143462-1,32"},
			errors:       []error{initialErr, nil},
		}
		previousDependencies := dependencies
		DeferCleanup(func() { dependencies = previousDependencies })
		dependencies.AppStore = store
		dependencies.Logger = log.NewLogger(log.Args{Writer: &buf})
		ctx := context.WithValue(context.Background(), interactiveKey, false)
		cmd := listPurchasesCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{})

		Expect(cmd.Execute()).To(Succeed())
		Expect(store.loginInputs).To(Equal([]appstore.LoginInput{{Context: ctx, Email: "user@example.com", Password: "secret"}}))
		Expect(store.input.Account.StoreFront).To(Equal("143462-1,32"))
		Expect(buf.String()).To(ContainSubstring(`"sessionRefreshed":true`))
		Expect(buf.String()).To(ContainSubstring(`"storeFront":"143462-1,32"`))
	},
		Entry("expired password token", appstore.ErrPasswordTokenExpired),
		Entry("missing Store AMD provisioning", fmt.Errorf("generate Store AMD proof: %w", appstore.ErrStoreAMDNotProvisioned)),
	)
})

type fakePurchasesAppStore struct {
	appstore.AppStore
	account      appstore.Account
	loginAccount appstore.Account
	loginInputs  []appstore.LoginInput
	errors       []error
	calls        int
	input        appstore.OwnedAppsInput
}

func (s *fakePurchasesAppStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{Account: s.account}, nil
}

func (s *fakePurchasesAppStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	s.loginInputs = append(s.loginInputs, input)

	return appstore.LoginOutput{Account: s.loginAccount}, nil
}

func (s *fakePurchasesAppStore) OwnedApps(input appstore.OwnedAppsInput) (appstore.OwnedAppsOutput, error) {
	s.input = input
	idx := s.calls
	s.calls++
	if idx < len(s.errors) && s.errors[idx] != nil {
		return appstore.OwnedAppsOutput{}, s.errors[idx]
	}

	return appstore.OwnedAppsOutput{}, nil
}
