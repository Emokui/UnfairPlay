//go:build darwin && !ios && cgo

package cmd

import (
	"fmt"
	"slices"
	"syscall"

	gokeychain "github.com/byteness/go-keychain"
	"github.com/byteness/keyring"
	"github.com/majd/ipatool/v2/pkg/keychain"
)

type macKeyring struct {
	keyring.Keyring
	service string
	path    string
}

func (*macKeyring) desktopSessionFD(fd int) {
	syscall.CloseOnExec(fd)
}

func openKeyring(config keyring.Config) (keychain.Keyring, error) {
	if config.AllowedBackends == nil || slices.Contains(config.AllowedBackends, keyring.KeychainBackend) {
		native := config
		native.AllowedBackends = []keyring.BackendType{keyring.KeychainBackend}
		if ring, err := keyring.Open(native); err == nil {
			path := ""
			if config.KeychainName != "" {
				path = config.KeychainName + ".keychain"
			}
			return &macKeyring{Keyring: ring, service: config.ServiceName, path: path}, nil
		}
	}
	return keyring.Open(config)
}

func (k *macKeyring) Get(key string) (keyring.Item, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)
	if k.path != "" {
		query.SetMatchSearchList(gokeychain.NewWithPath(k.path))
	}
	results, err := gokeychain.QueryItem(query)
	// A denied/cancelled read must never be mistaken for an absent master key.
	if err != nil {
		return keyring.Item{}, fmt.Errorf("read macOS keychain item: %w", err)
	}
	if len(results) == 0 {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return keyring.Item{Key: key, Data: results[0].Data, Label: results[0].Label, Description: results[0].Description}, nil
}
