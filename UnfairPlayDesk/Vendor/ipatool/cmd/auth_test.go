package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Login command", func() {
	var store *fakeLoginAppStore

	BeforeEach(func() {
		previousDependencies := dependencies
		DeferCleanup(func() { dependencies = previousDependencies })
		store = &fakeLoginAppStore{}
		dependencies.AppStore = store
		dependencies.Logger = log.NewLogger(log.Args{})
	})

	DescribeTable("requires credentials in non-interactive mode", func(args []string, message string) {
		cmd := loginCmd()
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
		cmd.SetArgs(args)

		Expect(cmd.Execute()).To(MatchError(message))
		Expect(store.loginCalls).To(BeZero())
	},
		Entry("missing Apple ID", []string{"--password", "secret"}, "an Apple ID is required when not running in interactive mode; use the \"--email\" flag"),
		Entry("missing password", []string{"--email", "user@example.com"}, "password is required when not running in interactive mode; use the \"--password\" flag"),
	)

	DescribeTable("uses supplied credentials", func(interactive bool, appleID string) {
		cmd := loginCmd()
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, interactive))
		cmd.SetArgs([]string{"--email", appleID, "--password", "secret"})

		Expect(cmd.Execute()).To(Succeed())
		Expect(store.loginCalls).To(Equal(1))
		Expect(store.input).To(Equal(appstore.LoginInput{Context: cmd.Context(), Email: appleID, Password: "secret"}))
	},
		Entry("interactive email", true, "user@example.com"),
		Entry("non-interactive email", false, "user@example.com"),
		Entry("interactive Chinese phone number", true, "+8613912345678"),
		Entry("non-interactive Chinese phone number", false, "+8613912345678"),
		Entry("interactive Indian phone number", true, "9123456789"),
		Entry("non-interactive Indian phone number", false, "9123456789"),
	)

	DescribeTable("only retries an uncertain sign-in after a code is provided", func(firstError error, input, code string, interactive bool) {
		store.firstError = firstError
		dir := GinkgoT().TempDir()
		inputPath := filepath.Join(dir, "stdin")
		Expect(os.WriteFile(inputPath, []byte(input), 0600)).To(Succeed())
		stdin, err := os.Open(inputPath)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(stdin.Close)
		stderr, err := os.Create(filepath.Join(dir, "stderr"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(stderr.Close)
		previousStdin, previousStderr := os.Stdin, os.Stderr
		os.Stdin, os.Stderr = stdin, stderr
		DeferCleanup(func() { os.Stdin, os.Stderr = previousStdin, previousStderr })

		cmd := loginCmd()
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, interactive))
		cmd.SetArgs([]string{"--email", "user@example.com", "--password", "synthetic"})
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		err = cmd.Execute()
		if code == "" {
			Expect(err).To(MatchError(firstError))
			Expect(store.loginCalls).To(Equal(1))
		} else {
			Expect(err).NotTo(HaveOccurred())
			Expect(store.loginCalls).To(Equal(2))
			Expect(store.input.AuthCode).To(Equal(code))
		}
		prompt, err := os.ReadFile(stderr.Name())
		Expect(err).NotTo(HaveOccurred())
		if interactive && firstError == appstore.ErrAuthenticationAmbiguous {
			Expect(string(prompt)).To(ContainSubstring("If you received a code"))
		} else {
			Expect(prompt).To(BeEmpty())
		}
	},
		Entry("rejects a known bad password immediately", appstore.ErrInvalidCredentials, "", "", true),
		Entry("leaves an uncertain noninteractive sign-in as an error", appstore.ErrAuthenticationAmbiguous, "", "", false),
		Entry("declines an uncertain sign-in with a blank response", appstore.ErrAuthenticationAmbiguous, "\n", "", true),
		Entry("retries with a code the user already received", appstore.ErrAuthenticationAmbiguous, "123456\n", "123456", true),
	)

	DescribeTable("reports the storefront without exposing credentials", func(info bool) {
		store.account = appstore.Account{Name: "Test", Email: "test@example.com", StoreFront: "143462-1,32", Password: "stored-secret", PasswordToken: "stored-token"}
		var output bytes.Buffer
		dependencies.Logger = log.NewLogger(log.Args{Writer: &output})
		cmd := loginCmd()
		args := []string{"--email", "test@example.com", "--password", "synthetic-password"}
		if info {
			cmd = infoCmd()
			args = nil
		}
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, false))
		cmd.SetArgs(args)
		Expect(cmd.Execute()).To(Succeed())
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		var result map[string]interface{}
		Expect(json.Unmarshal([]byte(lines[len(lines)-1]), &result)).To(Succeed())
		Expect(result["storeFront"]).To(Equal("143462-1,32"))
		Expect(result["email"]).To(Equal("test@example.com"))
		Expect(output.String()).NotTo(ContainSubstring("stored-secret"))
		Expect(output.String()).NotTo(ContainSubstring("stored-token"))
	}, Entry("login", false), Entry("account info", true))

	DescribeTable("prompts for an Apple ID", func(input, appleID, message string) {
		dir := GinkgoT().TempDir()
		inputPath := filepath.Join(dir, "stdin")
		Expect(os.WriteFile(inputPath, []byte(input), 0o600)).To(Succeed())
		stdin, err := os.Open(inputPath)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(stdin.Close)
		stderr, err := os.Create(filepath.Join(dir, "stderr"))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(stderr.Close)

		previousStdin, previousStderr := os.Stdin, os.Stderr
		os.Stdin, os.Stderr = stdin, stderr
		DeferCleanup(func() { os.Stdin, os.Stderr = previousStdin, previousStderr })

		cmd := loginCmd()
		cmd.SetContext(context.WithValue(context.Background(), interactiveKey, true))
		cmd.SetArgs([]string{"--password", "secret"})
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		err = cmd.Execute()
		if message == "" {
			Expect(err).NotTo(HaveOccurred())
			Expect(store.loginCalls).To(Equal(1))
			Expect(store.input).To(Equal(appstore.LoginInput{Context: cmd.Context(), Email: appleID, Password: "secret"}))
		} else {
			Expect(err).To(MatchError(message))
			Expect(store.loginCalls).To(BeZero())
		}

		prompt, err := os.ReadFile(stderr.Name())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(prompt)).To(Equal("enter Apple ID (email address or phone number): "))
	},
		Entry("reads email without requiring a terminal", "user@example.com\n", "user@example.com", ""),
		Entry("reads a phone number without requiring a terminal", "+91 91234-56789\n", "+91 91234-56789", ""),
		Entry("reports input errors", "", "", "failed to read Apple ID: failed to read input: EOF"),
	)
})

type fakeLoginAppStore struct {
	account appstore.Account
	appstore.AppStore
	input      appstore.LoginInput
	loginCalls int
	firstError error
}

func (f *fakeLoginAppStore) Login(input appstore.LoginInput) (appstore.LoginOutput, error) {
	f.input = input
	f.loginCalls++
	if f.loginCalls == 1 && f.firstError != nil {
		return appstore.LoginOutput{}, f.firstError
	}

	return appstore.LoginOutput{Account: f.account}, nil
}

func (f *fakeLoginAppStore) AccountInfo() (appstore.AccountInfoOutput, error) {
	return appstore.AccountInfoOutput{Account: f.account}, nil
}
