package keychain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/byteness/keyring"
)

type sessionTestKeychain struct {
	mu        sync.Mutex
	values    map[string][]byte
	gets      map[string]int
	sets      map[string]int
	getErr    map[string]error
	removeErr map[string]error
}

func newSessionTestKeychain() *sessionTestKeychain {
	return &sessionTestKeychain{values: map[string][]byte{}, gets: map[string]int{}, sets: map[string]int{}, getErr: map[string]error{}, removeErr: map[string]error{}}
}

func (k *sessionTestKeychain) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gets[key]++
	if err := k.getErr[key]; err != nil {
		return nil, err
	}
	value, ok := k.values[key]
	if !ok {
		return nil, keyring.ErrKeyNotFound
	}
	return bytes.Clone(value), nil
}

func (k *sessionTestKeychain) Set(key string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sets[key]++
	k.values[key] = bytes.Clone(value)
	return nil
}

func (k *sessionTestKeychain) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.removeErr[key]; err != nil {
		return err
	}
	delete(k.values, key)
	return nil
}

func TestSessionReadWithoutCredentialsDoesNotCreateSession(t *testing.T) {
	legacy := newSessionTestKeychain()
	directory := t.TempDir()
	store := NewSession(context.Background(), directory, "account-a", legacy)
	if _, err := store.Get("account"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("read empty profile: %v", err)
	}
	if len(legacy.sets) != 0 {
		t.Fatal("read created a session key")
	}
	if _, err := os.Stat(filepath.Join(directory, sessionFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created an encrypted session: %v", err)
	}
	if err := store.Set("account", []byte("first login")); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get("account"); err != nil || string(value) != "first login" || legacy.sets[sessionMasterKey] != 1 {
		t.Fatalf("first login did not persist with one key: %q, %v", value, err)
	}
}

func TestSessionMigrationAndReuse(t *testing.T) {
	legacy := newSessionTestKeychain()
	legacy.values["account"] = []byte(`{"email":"test@example.com","password":"synthetic-secret"}`)
	legacy.values["anisette-v4"] = []byte("synthetic-device-state")
	legacy.values["kbsync-v1"] = []byte("obsolete-cache")
	directory := t.TempDir()
	store := NewSession(context.Background(), directory, "account-a", legacy)
	account, err := store.Get("account")
	if err != nil || !bytes.Contains(account, []byte("synthetic-secret")) {
		t.Fatalf("migration: %s, %v", account, err)
	}
	if _, err := store.Get("anisette-v4"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("kbsync-v1"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("cache migrated: %v", err)
	}
	if err := store.Set("kbsync-v1", []byte("rebuilt-cache")); err != nil {
		t.Fatal(err)
	}
	if legacy.gets["kbsync-v1"] != 0 || legacy.gets[sessionMasterKey] != 1 || legacy.sets[sessionMasterKey] != 1 {
		t.Fatalf("unexpected keychain access: gets=%v sets=%v", legacy.gets, legacy.sets)
	}
	if len(legacy.values) != 1 || len(legacy.values[sessionMasterKey]) != 32 {
		t.Fatal("legacy credentials remain")
	}
	path := filepath.Join(directory, sessionFilename)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("synthetic-secret")) || bytes.Contains(ciphertext, []byte("synthetic-device-state")) {
		t.Fatal("plaintext on disk")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("file mode: %v, %v", info, err)
	}
	reopened := NewSession(context.Background(), directory, "account-a", legacy)
	if value, err := reopened.Get("account"); err != nil || !bytes.Equal(value, account) {
		t.Fatalf("reopen: %s, %v", value, err)
	}
	if _, err := reopened.Get("kbsync-v1"); err != nil {
		t.Fatal(err)
	}
	if legacy.gets[sessionMasterKey] != 2 || legacy.gets["account"] != 1 || legacy.gets["anisette-v4"] != 1 {
		t.Fatalf("repeated legacy/key reads: %v", legacy.gets)
	}
}

func TestSessionDenialTamperingAndRevocation(t *testing.T) {
	legacy := newSessionTestKeychain()
	directory := t.TempDir()
	store := NewSession(context.Background(), directory, "account-a", legacy)
	if err := store.Set("account", []byte("original")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, sessionFilename)
	original, _ := os.ReadFile(path)
	master := bytes.Clone(legacy.values[sessionMasterKey])
	denied := errors.New("synthetic access denied")
	legacy.getErr[sessionMasterKey] = denied
	reopened := NewSession(context.Background(), directory, "account-a", legacy)
	if err := reopened.Set("account", []byte("replacement")); !errors.Is(err, denied) {
		t.Fatalf("denial ignored: %v", err)
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(original, unchanged) || !bytes.Equal(master, legacy.values[sessionMasterKey]) {
		t.Fatal("denial changed credentials")
	}
	delete(legacy.getErr, sessionMasterKey)
	corrupt := bytes.Clone(original)
	corrupt[len(corrupt)-1] ^= 1
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Set("account", []byte("replacement")); err == nil {
		t.Fatal("tampering accepted")
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	otherAccount := NewSession(context.Background(), directory, "account-b", legacy)
	if _, err := otherAccount.Get("account"); err == nil {
		t.Fatal("cross-account ciphertext accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	legacy.getErr[sessionMasterKey] = denied
	reads := legacy.gets[sessionMasterKey]
	if err := reopened.(interface{ Revoke() error }).Revoke(); err != nil {
		t.Fatal(err)
	}
	if legacy.gets[sessionMasterKey] != reads || len(legacy.values) != 0 {
		t.Fatal("revoke read key or retained credentials")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ciphertext retained: %v", err)
	}
}

func TestSessionConcurrentUpdatesAndStaleWriter(t *testing.T) {
	legacy := newSessionTestKeychain()
	directory := t.TempDir()
	store := NewSession(context.Background(), directory, "account-a", legacy)
	if err := store.Set("account", []byte("original")); err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	for _, key := range []string{"anisette-v4", "kbsync-v1"} {
		work.Add(1)
		go func(key string) {
			defer work.Done()
			other := NewSession(context.Background(), directory, "account-a", legacy)
			if err := other.Set(key, []byte(key)); err != nil {
				t.Error(err)
			}
		}(key)
	}
	work.Wait()
	for _, key := range []string{"account", "anisette-v4", "kbsync-v1"} {
		if _, err := store.Get(key); err != nil {
			t.Fatal(err)
		}
	}
	revoker := NewSession(context.Background(), directory, "account-a", legacy)
	if err := revoker.(interface{ Revoke() error }).Revoke(); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("account", []byte("stale")); err == nil {
		t.Fatal("stale writer resurrected revoked session")
	}
	newLogin := NewSession(context.Background(), directory, "account-a", legacy)
	if err := newLogin.Set("account", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("account", []byte("stale")); err == nil {
		t.Fatal("stale writer replaced new session")
	}
	if value, err := newLogin.Get("account"); err != nil || string(value) != "fresh" {
		t.Fatalf("new login damaged: %s, %v", value, err)
	}
}

func TestSessionInterruptedMigrationCleanup(t *testing.T) {
	legacy := newSessionTestKeychain()
	legacy.values["account"] = []byte("original")
	legacy.removeErr["account"] = errors.New("synthetic deletion cancelled")
	directory := t.TempDir()
	store := NewSession(context.Background(), directory, "account-a", legacy)
	if _, err := store.Get("account"); err == nil {
		t.Fatal("cleanup failure ignored")
	}
	if len(legacy.values[sessionMasterKey]) != 32 || len(legacy.values["account"]) == 0 {
		t.Fatal("migration lost credentials")
	}
	delete(legacy.removeErr, "account")
	reopened := NewSession(context.Background(), directory, "account-a", legacy)
	if value, err := reopened.Get("account"); err != nil || string(value) != "original" {
		t.Fatalf("migration recovery: %s, %v", value, err)
	}
	if legacy.gets["account"] != 1 {
		t.Fatal("recovery reread legacy credential")
	}
	if len(legacy.values) != 1 {
		t.Fatal("legacy cleanup incomplete")
	}
}
