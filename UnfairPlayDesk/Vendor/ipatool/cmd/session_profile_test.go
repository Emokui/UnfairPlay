package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

func TestIndependentSessionStorage(t *testing.T) {
	home := t.TempDir()
	a := "1A1ADE01-43A8-4C8B-9D9F-711D3B5FEAA8"
	b := "6252B7C7-7A9C-4010-82E6-5DCB1B773C17"
	ad, ak, err := sessionNamespace(home, a)
	if err != nil {
		t.Fatal(err)
	}
	bd, bk, err := sessionNamespace(home, b)
	if err != nil {
		t.Fatal(err)
	}
	if ad == bd || ak == bk || ak == KeychainServiceName || bk == KeychainServiceName {
		t.Fatal("accounts share a namespace")
	}
	if ad2, ak2, _ := sessionNamespace(home, strings.ToLower(a)); ad2 != ad || ak2 != ak {
		t.Fatal("UUID case changes session")
	}
	for dir, token := range map[string]string{ad: "session-a", bd: "session-b"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cookies"), []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := os.ReadFile(filepath.Join(ad, "cookies"))
	if string(got) != "session-a" {
		t.Fatal("account B overwrote account A")
	}
	// A failed/cleared login for B must not touch A.
	if err := os.Remove(filepath.Join(bd, "cookies")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(ad, "cookies")); string(got) != "session-a" {
		t.Fatal("clearing B affected A")
	}
	if d, k, err := sessionNamespace(home, ""); err != nil || d != "" || k != KeychainServiceName {
		t.Fatal("legacy configuration changed")
	}
}

func TestInvalidSessionProfiles(t *testing.T) {
	for _, profile := range []string{"../other", "/tmp/session", "test", "1A1ADE01-43A8-4C8B-9D9F-711D3B5FEAA8/../x"} {
		if _, _, err := sessionNamespace(t.TempDir(), profile); err == nil {
			t.Errorf("accepted unsafe profile %q", profile)
		}
	}
}

func TestProfileSessionSymlinkRejectionAndCorruptCookieRevoke(t *testing.T) {
	home := t.TempDir()
	profile := "1A1ADE01-43A8-4C8B-9D9F-711D3B5FEAA8"

	dir, _, err := prepareProfileSessionDirectory(home, profile)
	if err != nil {
		t.Fatalf("prepare session directory failed: %v", err)
	}
	cookiePath := filepath.Join(dir, CookieJarFileName)
	lockPath := cookiePath + ".lock"
	if err := os.WriteFile(cookiePath, []byte("{{{corrupt-cookie-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}

	corruptDefaultJar := filepath.Join(home, "corrupt-default-cookies")
	if err := os.WriteFile(corruptDefaultJar, []byte("{{{corrupt-default"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCOOKIES", corruptDefaultJar)

	if _, err := openCookieJar(dir, true); err == nil {
		t.Fatal("expected corrupt cookie jar to fail normal load with error")
	}
	transientJar, err := openCookieJar(dir, false)
	if err != nil {
		t.Fatalf("revoke mode must bypass corrupt cookie jar without touching GOCOOKIES: %v", err)
	}
	if err := transientJar.Save(); err != nil {
		t.Fatalf("transient cookie jar save must be a no-op: %v", err)
	}
	if err := removeSessionCookies(dir); err != nil {
		t.Fatalf("removeSessionCookies failed: %v", err)
	}
	for _, p := range []string{cookiePath, lockPath} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s removed, got %v", p, err)
		}
	}

	// Symlink XDG_STATE_HOME parent directory must be rejected by prepareStateDirectory.
	xdgReal := filepath.Join(home, "xdg-real")
	if err := os.MkdirAll(xdgReal, 0700); err != nil {
		t.Fatal(err)
	}
	xdgLink := filepath.Join(home, "xdg-link")
	if err := os.Symlink(xdgReal, xdgLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", xdgLink)
	if _, err := prepareStateDirectory(operatingsystem.New(), home); err == nil {
		t.Fatal("accepted symlink XDG_STATE_HOME parent directory")
	}
	if _, err := os.Lstat(filepath.Join(xdgReal, "ipatool")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created directory inside symlink target: %v", err)
	}

	// Symlink at profile directory must be rejected without modifying target mode.
	victim := filepath.Join(home, "victim-dir")
	if err := os.MkdirAll(victim, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0755); err != nil {
		t.Fatal(err)
	}
	otherProfile := "6252B7C7-7A9C-4010-82E6-5DCB1B773C17"
	linkedDir := filepath.Join(home, "Library", "Application Support", "UnfairPlayDesk", "Sessions", strings.ToLower(otherProfile))
	if err := os.Symlink(victim, linkedDir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareProfileSessionDirectory(home, otherProfile); err == nil {
		t.Fatal("accepted symlink session directory")
	}
	info, err := os.Stat(victim)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("symlink target permissions modified: %v, %v", info, err)
	}

	root := rootCmd()
	revokeTarget, _, err := root.Find([]string{"auth", "revoke"})
	if err != nil || !isAuthRevokeCommand(revokeTarget) {
		t.Fatalf("expected auth revoke command detection, got %v, %v", revokeTarget, err)
	}
	loginTarget, _, err := root.Find([]string{"auth", "login"})
	if err != nil || isAuthRevokeCommand(loginTarget) {
		t.Fatalf("unexpected revoke detection on auth login: %v", err)
	}
}

func TestPassphrasePromptTargetNeverPanics(t *testing.T) {
	if got := passphrasePromptTarget("Enter passphrase to unlock /tmp/keyring:", "/fallback"); got != "/tmp/keyring:" {
		t.Fatalf("unexpected target with unlock token: %q", got)
	}
	if got := passphrasePromptTarget("Enter new keyring passphrase", "/fallback"); got != "Enter new keyring passphrase" {
		t.Fatalf("unexpected target without unlock token: %q", got)
	}
	if got := passphrasePromptTarget("   ", "/fallback"); got != "/fallback" {
		t.Fatalf("expected fallback for blank prompt, got %q", got)
	}
}
