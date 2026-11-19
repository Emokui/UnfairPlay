package keychain

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/byteness/keyring"
	"github.com/majd/ipatool/v2/internal/cachelock"
)

const sessionMasterKey = "session-master-v1"
const sessionFilename = "session-v1.enc"

var legacySessionKeys = []string{"account", "anisette-v4", "kbsync-v1"}

type sessionData struct {
	Version       int               `json:"version"`
	LegacyCleaned bool              `json:"legacy_cleaned"`
	Values        map[string][]byte `json:"values"`
}

type session struct {
	mu         sync.Mutex
	ctx        context.Context
	directory  string
	namespace  string
	legacy     Keychain
	master     []byte
	desktop    *os.File
	desktopErr error
	loaded     bool
	revoked    bool
}

// NewSession opens credentials lazily. Only the fixed encryption key remains in
// the keychain. Each operation reloads the encrypted file under a process lock,
// so independent CLI processes cannot overwrite one another's token updates.
func NewSession(ctx context.Context, directory, namespace string, legacy Keychain) Keychain {
	return &session{ctx: ctx, directory: directory, namespace: namespace, legacy: legacy}
}

func (s *session) locked(operation func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := cachelock.Acquire(s.ctx, filepath.Join(s.directory, ".session.lock"))
	if err != nil {
		return fmt.Errorf("lock account session: %w", err)
	}
	defer unlock()
	return operation()
}

func (s *session) Get(key string) ([]byte, error) {
	var value []byte
	err := s.locked(func() error {
		data, err := s.load(false)
		if err != nil {
			return err
		}
		var found bool
		value, found = data.Values[key]
		if !found {
			return keyring.ErrKeyNotFound
		}
		return nil
	})
	return value, err
}

func (s *session) Set(key string, value []byte) error {
	return s.locked(func() error {
		data, err := s.load(true)
		if err != nil {
			return err
		}
		if previous, found := data.Values[key]; found && bytes.Equal(previous, value) {
			return nil
		}
		data.Values[key] = value
		return s.save(data)
	})
}

func (s *session) Remove(key string) error {
	return s.locked(func() error {
		data, err := s.load(false)
		if err != nil {
			return err
		}
		if _, found := data.Values[key]; !found {
			return nil
		}
		delete(data.Values, key)
		return s.save(data)
	})
}

func (s *session) load(create bool) (sessionData, error) {
	if s.revoked {
		return sessionData{}, errors.New("account session was cleared; sign in again")
	}
	encoded, err := os.ReadFile(filepath.Join(s.directory, sessionFilename))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return sessionData{}, fmt.Errorf("read encrypted account session: %w", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		if s.loaded {
			return sessionData{}, errors.New("account session was cleared by another process; sign in again")
		}
		return s.migrate(create)
	}
	if err := s.loadMaster(false); err != nil {
		return sessionData{}, err
	}
	data, err := s.decode(encoded)
	if err != nil {
		return sessionData{}, err
	}
	s.loaded = true
	if !data.LegacyCleaned {
		if err := s.cleanLegacy(); err != nil {
			return sessionData{}, err
		}
		data.LegacyCleaned = true
		if err := s.save(data); err != nil {
			return sessionData{}, err
		}
	}
	return data, nil
}

func (s *session) loadMaster(create bool) error {
	if s.master != nil {
		return nil
	}
	if s.desktop != nil {
		command := byte('R')
		if create {
			command = 'C'
		}
		key, err := s.desktopRequest(command)
		if err == nil {
			s.master = key
		}
		return err
	}
	key, err := s.legacy.Get(sessionMasterKey)
	if errors.Is(err, keyring.ErrKeyNotFound) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("generate account session key: %w", err)
		}
		if err := s.legacy.Set(sessionMasterKey, key); err != nil {
			return fmt.Errorf("save account session key: %w", err)
		}
	} else if errors.Is(err, keyring.ErrKeyNotFound) {
		return errors.New("account session key is missing; clear this account login and sign in again")
	} else if err != nil {
		return fmt.Errorf("read account session key: %w", err)
	}
	if len(key) != 32 {
		return errors.New("account session key is invalid; clear this account login and sign in again")
	}
	s.master = append([]byte(nil), key...)
	return nil
}

func (s *session) migrate(create bool) (sessionData, error) {
	data := sessionData{Version: 1, Values: make(map[string][]byte)}
	// kbsync is reproducible and intentionally never read during migration.
	for _, key := range legacySessionKeys[:2] {
		value, err := s.legacy.Get(key)
		if errors.Is(err, keyring.ErrKeyNotFound) || errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return sessionData{}, fmt.Errorf("migrate %s: %w", key, err)
		}
		data.Values[key] = value
	}
	if !create && len(data.Values) == 0 {
		return data, nil
	}
	if err := s.loadMaster(true); err != nil {
		return sessionData{}, err
	}
	if err := s.save(data); err != nil {
		return sessionData{}, err
	}
	// Verify the committed ciphertext before removing any legacy credentials.
	encoded, err := os.ReadFile(filepath.Join(s.directory, sessionFilename))
	if err != nil {
		return sessionData{}, err
	}
	if _, err := s.decode(encoded); err != nil {
		return sessionData{}, err
	}
	s.loaded = true
	if err := s.cleanLegacy(); err != nil {
		return sessionData{}, err
	}
	data.LegacyCleaned = true
	return data, s.save(data)
}

func (s *session) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.master)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *session) decode(encoded []byte) (sessionData, error) {
	aead, err := s.aead()
	if err != nil {
		return sessionData{}, err
	}
	if len(encoded) < aead.NonceSize()+aead.Overhead() {
		return sessionData{}, errors.New("encrypted account session is truncated; clear this account login and sign in again")
	}
	plaintext, err := aead.Open(nil, encoded[:aead.NonceSize()], encoded[aead.NonceSize():], []byte(s.namespace))
	if err != nil {
		return sessionData{}, errors.New("encrypted account session failed authentication; clear this account login and sign in again")
	}
	var data sessionData
	if err := json.Unmarshal(plaintext, &data); err != nil || data.Version != 1 || data.Values == nil {
		return sessionData{}, errors.New("invalid encrypted account session format")
	}
	return data, nil
}

func (s *session) save(data sessionData) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}
	aead, err := s.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	encoded := aead.Seal(nonce, nonce, plaintext, []byte(s.namespace))
	file, err := os.CreateTemp(s.directory, ".session-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(s.directory, sessionFilename))
}

func (s *session) cleanLegacy() error {
	var failures []error
	for _, key := range legacySessionKeys {
		if err := s.legacy.Remove(key); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) && !errors.Is(err, fs.ErrNotExist) {
			failures = append(failures, fmt.Errorf("remove legacy %s: %w", key, err))
		}
	}
	return errors.Join(failures...)
}

// Revoke deletes without reading the key or decrypting the file. This also
// permits clearing an account whose encrypted state or key is damaged.
func (s *session) Revoke() error {
	return s.locked(func() error {
		if err := s.cleanLegacy(); err != nil {
			return err
		}
		var err error
		if s.desktop != nil {
			_, err = s.desktopRequest('D')
		} else {
			err = s.legacy.Remove(sessionMasterKey)
		}
		if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove account session key: %w", err)
		}
		clear(s.master)
		s.master = nil
		s.revoked = true
		paths, err := filepath.Glob(filepath.Join(s.directory, ".session-*.tmp"))
		if err != nil {
			return err
		}
		paths = append(paths, filepath.Join(s.directory, sessionFilename))
		var failures []error
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				failures = append(failures, fmt.Errorf("remove encrypted account session: %w", err))
			}
		}
		return errors.Join(failures...)
	})
}
