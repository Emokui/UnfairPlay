package appstore

import (
	"errors"
	"io/fs"

	"github.com/byteness/keyring"
	"github.com/majd/ipatool/v2/pkg/keychain"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
)

var _ = Describe("AppStore (Revoke)", func() {
	var (
		ctrl         *gomock.Controller
		appstore     AppStore
		mockKeychain *keychain.MockKeychain
		stateErr     error
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		mockKeychain = keychain.NewMockKeychain(ctrl)
		stateErr = nil
		mockKeychain.EXPECT().Remove(anisetteKeychainKey).DoAndReturn(func(string) error { return stateErr })
		appstore = NewAppStore(Args{
			Keychain: mockKeychain,
		})
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	It("reports failure to clear the new device authentication state", func() {
		stateErr = errors.New("state unavailable")
		mockKeychain.EXPECT().Remove("account").Return(nil)
		mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(nil)
		Expect(appstore.Revoke()).To(MatchError("failed to remove Apple authentication state: state unavailable"))
	})
	It("clears a legacy profile without device authentication state", func() {
		stateErr = keyring.ErrKeyNotFound
		mockKeychain.EXPECT().Remove("account").Return(nil)
		mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(nil)
		Expect(appstore.Revoke()).To(Succeed())
	})
	When("keychain removes item", func() {
		BeforeEach(func() {
			mockKeychain.EXPECT().
				Remove("account").
				Return(nil)
			mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(nil)
		})

		It("returns data", func() {
			err := appstore.Revoke()
			Expect(err).ToNot(HaveOccurred())
		})
	})

	DescribeTable("revokes accounts saved before a kbsync cache existed", func(missing error) {
		mockKeychain.EXPECT().Remove("account").Return(nil)
		mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(missing)
		Expect(appstore.Revoke()).To(Succeed())
	},
		Entry("native keychain", keyring.ErrKeyNotFound),
		Entry("file keychain", &fs.PathError{Op: "remove", Path: "cache", Err: fs.ErrNotExist}),
	)

	DescribeTable("clearing an already logged-out profile succeeds", func(missing error) {
		mockKeychain.EXPECT().Remove("account").Return(missing)
		mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(missing)
		Expect(appstore.Revoke()).To(Succeed())
	},
		Entry("native keychain", keyring.ErrKeyNotFound),
		Entry("file keychain", &fs.PathError{Op: "remove", Path: "account", Err: fs.ErrNotExist}),
	)

	It("reports a cache removal failure after removing the account", func() {
		mockKeychain.EXPECT().Remove("account").Return(nil)
		mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(errors.New("cache unavailable"))
		Expect(appstore.Revoke()).To(MatchError("failed to remove kbsync cache from keychain: cache unavailable"))
	})

	When("keychain returns error", func() {
		BeforeEach(func() {
			mockKeychain.EXPECT().
				Remove("account").
				Return(errors.New(""))
			mockKeychain.EXPECT().Remove(kbsyncCacheKey).Return(nil)
		})

		It("returns wrapped error", func() {
			err := appstore.Revoke()
			Expect(err).To(HaveOccurred())
		})
	})
})
