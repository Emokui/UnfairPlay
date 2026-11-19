package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Get Version Metadata command", func() {
	DescribeTable("passes the platform and exact version to metadata lookup", func(args []string, platform appstore.Platform, lookup bool) {
		store := &fakeVersionMetadataAppStore{}
		previous := dependencies
		DeferCleanup(func() { dependencies = previous })
		dependencies.AppStore = store
		dependencies.Logger = log.NewLogger(log.Args{})
		cmd := getVersionMetadataCmd()
		cmd.SetArgs(append(args, "--external-version-id", "876660716"))
		Expect(cmd.Execute()).To(Succeed())
		Expect(store.input.Platform).To(Equal(platform))
		Expect(store.input.VersionID).To(Equal("876660716"))
		Expect(store.input.App.ID).To(Equal(int64(42)))
		Expect(store.lookupCalled).To(Equal(lookup))
		if lookup {
			Expect(store.lookupInput.Platform).To(Equal(platform))
		}
	},
		Entry("Mac bundle", []string{"-b", "com.example.mac", "--platform", "macos"}, appstore.PlatformMacOS, true),
		Entry("Mac ID alias", []string{"-i", "42", "--platform", "mac"}, appstore.PlatformMacOS, false),
		Entry("default", []string{"-i", "42"}, appstore.Platform(""), false),
	)
	It("rejects unknown as a filter", func() {
		cmd := getVersionMetadataCmd()
		cmd.SetArgs([]string{"-i", "42", "--external-version-id", "123", "--platform", "unknown"})
		Expect(cmd.Execute()).To(MatchError(`invalid platform "unknown"`))
	})

	DescribeTable("refreshes sign-in once with command context and emits refreshed storefront", func(initialErr error) {
		var buf bytes.Buffer
		store := &fakeVersionMetadataAppStore{
			account:      appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143441"},
			loginAccount: appstore.Account{Email: "user@example.com", Password: "secret", StoreFront: "143462-1,32"},
			errors:       []error{initialErr, nil},
		}
		previous := dependencies
		DeferCleanup(func() { dependencies = previous })
		dependencies.Logger = log.NewLogger(log.Args{Writer: &buf})
		ctx := context.WithValue(context.Background(), interactiveKey, false)
		cmd := getVersionMetadataCmdWithAppStore(func() appstore.AppStore { return store })
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"-i", "42", "--external-version-id", "876660716"})

		Expect(cmd.Execute()).To(Succeed())
		Expect(store.accountInfoCalls).To(Equal(1))
		Expect(store.loginInputs).To(Equal([]appstore.LoginInput{{Context: ctx, Email: "user@example.com", Password: "secret"}}))
		Expect(store.input.Account.StoreFront).To(Equal("143462-1,32"))
		Expect(buf.String()).To(ContainSubstring(`"storeFront":"143462-1,32"`))
		Expect(buf.String()).To(ContainSubstring(`"email":"user@example.com"`))
		Expect(buf.String()).To(ContainSubstring(`"sessionRefreshed":true`))
	},
		Entry("expired password token", appstore.ErrPasswordTokenExpired),
		Entry("missing Store AMD provisioning", fmt.Errorf("generate Store AMD proof: %w", appstore.ErrStoreAMDNotProvisioned)),
	)

	It("rejects mismatched --expected-account before and after refreshing sign-in", func() {
		store := &fakeVersionMetadataAppStore{
			account: appstore.Account{Email: "wrong@example.com"},
		}
		cmd := getVersionMetadataCmdWithAppStore(func() appstore.AppStore { return store })
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
		cmd.SetArgs([]string{"-i", "42", "--external-version-id", "123", "--expected-account", "expected@example.com"})
		Expect(cmd.Execute()).To(MatchError("version metadata account does not match selected profile"))

		store = &fakeVersionMetadataAppStore{
			account:      appstore.Account{Email: "expected@example.com", Password: "secret"},
			loginAccount: appstore.Account{Email: "other@example.com"},
			errors:       []error{appstore.ErrPasswordTokenExpired, nil},
		}
		cmd = getVersionMetadataCmdWithAppStore(func() appstore.AppStore { return store })
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
		cmd.SetArgs([]string{"-i", "42", "--external-version-id", "123", "--expected-account", "expected@example.com"})
		Expect(cmd.Execute()).To(MatchError("version metadata account does not match selected profile after refreshing sign-in"))
	})

	It("preserves session-refresh cause when non-interactive refresh lacks a password", func() {
		store := &fakeVersionMetadataAppStore{
			account:  appstore.Account{Email: "user@example.com"},
			loginErr: errors.New("password is required to sign in"),
			errors:   []error{appstore.ErrStoreAMDNotProvisioned},
		}
		cmd := getVersionMetadataCmdWithAppStore(func() appstore.AppStore { return store })
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
		cmd.SetArgs([]string{"-i", "42", "--external-version-id", "123"})
		err := cmd.Execute()
		Expect(errors.Is(err, appstore.ErrStoreAMDNotProvisioned)).To(BeTrue())
	})
})

type fakeVersionMetadataAppStore struct {
	fakeListVersionsAppStore
	account          appstore.Account
	accountInfoCalls int
	loginAccount     appstore.Account
	loginErr         error
	loginInputs      []appstore.LoginInput
	errors           []error
	calls            int
	input            appstore.GetVersionMetadataInput
}

func (s *fakeVersionMetadataAppStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	s.accountInfoCalls++
	return appstore.AccountInfoOutput{Account: s.account}, nil
}

func (s *fakeVersionMetadataAppStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	s.loginInputs = append(s.loginInputs, input)
	return appstore.LoginOutput{Account: s.loginAccount}, s.loginErr
}

func (s *fakeVersionMetadataAppStore) GetVersionMetadata(input appstore.GetVersionMetadataInput) (appstore.GetVersionMetadataOutput, error) {
	s.input = input
	idx := s.calls
	s.calls++
	if idx < len(s.errors) && s.errors[idx] != nil {
		return appstore.GetVersionMetadataOutput{}, s.errors[idx]
	}

	return appstore.GetVersionMetadataOutput{DisplayVersion: "1.0"}, nil
}
