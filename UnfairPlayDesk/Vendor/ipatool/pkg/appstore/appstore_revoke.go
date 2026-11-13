package appstore

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/byteness/keyring"
)

func (t *appstore) Revoke() error {
	t.authStateMu.Lock()
	defer t.authStateMu.Unlock()
	t.anisetteState = nil
	t.authenticationHeaders = nil
	stateErr := t.keychain.Remove(anisetteKeychainKey)
	if errors.Is(stateErr, keyring.ErrKeyNotFound) || errors.Is(stateErr, fs.ErrNotExist) {
		stateErr = nil
	} else if stateErr != nil {
		stateErr = fmt.Errorf("failed to remove Apple authentication state: %w", stateErr)
	}
	accountErr := t.keychain.Remove("account")
	if errors.Is(accountErr, keyring.ErrKeyNotFound) || errors.Is(accountErr, fs.ErrNotExist) {
		accountErr = nil
	} else if accountErr != nil {
		accountErr = fmt.Errorf("failed to remove account from keychain: %w", accountErr)
	}

	t.kbsyncCache.mu.Lock()
	defer t.kbsyncCache.mu.Unlock()

	t.kbsyncCache.entry = kbsyncCacheEntry{}

	cacheErr := t.keychain.Remove(kbsyncCacheKey)
	if errors.Is(cacheErr, keyring.ErrKeyNotFound) || errors.Is(cacheErr, fs.ErrNotExist) {
		cacheErr = nil
	} else if cacheErr != nil {
		cacheErr = fmt.Errorf("failed to remove kbsync cache from keychain: %w", cacheErr)
	}

	return errors.Join(accountErr, cacheErr, stateErr)
}
