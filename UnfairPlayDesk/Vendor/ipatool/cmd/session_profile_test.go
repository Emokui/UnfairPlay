package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
