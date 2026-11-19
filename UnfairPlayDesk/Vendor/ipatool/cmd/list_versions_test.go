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

var _ = Describe("List Versions command", func() {
	DescribeTable("passes the selected platform to lookup and version listing", func(args []string, expected appstore.Platform, lookup bool) {
		store := &fakeListVersionsAppStore{}
		previous := dependencies
		DeferCleanup(func() { dependencies = previous })
		dependencies.AppStore = store
		dependencies.Logger = log.NewLogger(log.Args{})
		cmd := ListVersionsCmd()
		cmd.SetArgs(args)
		Expect(cmd.Execute()).To(Succeed())
		Expect(store.input.Platform).To(Equal(expected))
		Expect(store.input.App.ID).To(Equal(int64(42)))
		Expect(store.lookupCalled).To(Equal(lookup))
		if lookup {
			Expect(store.lookupInput.Platform).To(Equal(expected))
		}
	},
		Entry("Mac bundle ID", []string{"-b", "com.example.mac", "--platform", "macos"}, appstore.PlatformMacOS, true),
		Entry("Mac app ID alias", []string{"-i", "42", "--platform", "mac"}, appstore.PlatformMacOS, false),
		Entry("default platform", []string{"-i", "42"}, appstore.Platform(""), false),
		Entry("iOS alias", []string{"-i", "42", "--platform", "ios"}, appstore.PlatformIPhone, false),
	)

	It("rejects unknown as a platform before accessing the account", func() {
		cmd := ListVersionsCmd()
		cmd.SetArgs([]string{"-i", "42", "--platform", "unknown"})
		Expect(cmd.Execute()).To(MatchError(`invalid platform "unknown"`))
	})

	DescribeTable("refreshes sign-in once with command context and emits refreshed storefront", func(initialErr error) {
		var buf bytes.Buffer
		store := &fakeListVersionsAppStore{
			account:      appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143441"},
			loginAccount: appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143462-1,32"},
			errors:       []error{initialErr, nil},
		}
		previous := dependencies
		DeferCleanup(func() { dependencies = previous })
		dependencies.AppStore = store
		dependencies.Logger = log.NewLogger(log.Args{Writer: &buf})
		ctx := context.WithValue(context.Background(), interactiveKey, false)
		cmd := ListVersionsCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"-i", "42"})

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

type fakeListVersionsAppStore struct {
	appstore.AppStore
	account      appstore.Account
	loginAccount appstore.Account
	loginInputs  []appstore.LoginInput
	errors       []error
	calls        int
	input        appstore.ListVersionsInput
	lookupInput  appstore.LookupInput
	lookupCalled bool
}

func (s *fakeListVersionsAppStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{Account: s.account}, nil
}
func (s *fakeListVersionsAppStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	s.loginInputs = append(s.loginInputs, input)

	return appstore.LoginOutput{Account: s.loginAccount}, nil
}
func (s *fakeListVersionsAppStore) Lookup(input appstore.LookupInput) (appstore.LookupOutput, error) {
	s.lookupCalled = true
	s.lookupInput = input

	return appstore.LookupOutput{App: appstore.App{ID: 42, BundleID: input.BundleID}}, nil
}
func (s *fakeListVersionsAppStore) ListVersions(input appstore.ListVersionsInput) (appstore.ListVersionsOutput, error) {
	s.input = input
	idx := s.calls
	s.calls++
	if idx < len(s.errors) && s.errors[idx] != nil {
		return appstore.ListVersionsOutput{}, s.errors[idx]
	}

	return appstore.ListVersionsOutput{ExternalVersionIdentifiers: []string{"123"}}, nil
}
