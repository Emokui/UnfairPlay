package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/byteness/keyring"
	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/http"
	"github.com/majd/ipatool/v2/pkg/keychain"
	"github.com/majd/ipatool/v2/pkg/log"
	"github.com/majd/ipatool/v2/pkg/util"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var dependencies = Dependencies{}
var keychainPassphrase string

type Dependencies struct {
	Logger    log.Logger
	OS        operatingsystem.OperatingSystem
	Machine   machine.Machine
	CookieJar http.CookieJar
	Keychain  keychain.Keychain
	AppStore  appstore.AppStore
}

// newLogger returns a new logger instance.
func newLogger(format OutputFormat, verbose bool) log.Logger {
	var writer io.Writer

	switch format {
	case OutputFormatJSON:
		writer = zerolog.SyncWriter(os.Stdout)
	case OutputFormatText:
		writer = log.NewWriter()
	}

	return log.NewLogger(log.Args{
		Verbose: verbose,
		Writer:  writer,
	},
	)
}

type sessionCookieJar struct {
	*cookiejar.Jar
	mu    sync.Mutex
	dirty bool
}

func newCookieJar(stateDirectory string) http.CookieJar {
	return &sessionCookieJar{Jar: util.Must(cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(stateDirectory, CookieJarFileName),
	}))}
}

func (j *sessionCookieJar) SetCookies(url *url.URL, cookies []*stdhttp.Cookie) {
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.Jar.SetCookies(url, cookies)
	j.dirty = true
}

func (j *sessionCookieJar) Save() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.dirty {
		return nil
	}
	if err := j.Jar.Save(); err != nil {
		return err
	}
	j.dirty = false
	return nil
}

// newKeychain returns a new keychain instance.
func newKeychain(ctx context.Context, stateDirectory string, interactive bool, serviceName string) keychain.Keychain {
	ring := util.Must(openKeyring(keyring.Config{
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
			keyring.FileBackend,
		},
		ServiceName:              serviceName,
		KeychainTrustApplication: true,
		FileDir:                  stateDirectory,
		FilePasswordFunc: func(s string) (string, error) {
			if keychainPassphrase == "" && !interactive {
				return "", errors.New("keychain passphrase is required when not running in interactive mode; use the \"--keychain-passphrase\" flag")
			}

			if keychainPassphrase != "" {
				return keychainPassphrase, nil
			}

			path := strings.Split(s, " unlock ")[1]
			password, err := readPrompt(fmt.Sprintf("enter passphrase to unlock %s (this is separate from your Apple ID password): ", path), true)
			if err != nil {
				return "", fmt.Errorf("failed to read password: %w", err)
			}

			return password, nil
		},
	}))

	legacy := keychain.New(keychain.Args{
		Keyring: ring,
		Label:   serviceName,
	})
	if sessionProfile == "" {
		return legacy
	}
	if deskSessionFD >= 3 {
		channel := os.NewFile(uintptr(deskSessionFD), "desktop-session")
		if native, ok := ring.(interface{ desktopSessionFD(int) }); ok {
			native.desktopSessionFD(deskSessionFD)
			return keychain.NewDesktopSession(ctx, stateDirectory, serviceName, legacy, channel)
		}
		channel.Close()
	}
	return keychain.NewSession(ctx, stateDirectory, serviceName, legacy)
}

// initWithCommand initializes the dependencies of the command.
func initWithCommand(cmd *cobra.Command) {
	verbose := cmd.Flag("verbose").Value.String() == "true"
	interactive, _ := cmd.Context().Value(interactiveKey).(bool)
	format := util.Must(OutputFormatFromString(cmd.Flag("format").Value.String()))

	dependencies.Logger = newLogger(format, verbose)
	if cmd.Name() == "mcp" {
		dependencies.Logger = log.NewLogger(log.Args{Verbose: verbose, Writer: zerolog.SyncWriter(os.Stderr)})
	}

	dependencies.OS = operatingsystem.New()
	dependencies.Machine = machine.New(machine.Args{OS: dependencies.OS})
	var stateDirectory string
	serviceName := KeychainServiceName
	if sessionProfile == "" {
		stateDirectory = util.Must(prepareStateDirectory(dependencies.OS, dependencies.Machine.HomeDirectory()))
	} else {
		var err error
		stateDirectory, serviceName, err = sessionNamespace(dependencies.Machine.HomeDirectory(), sessionProfile)
		if err != nil {
			panic(err)
		}
		if err := os.MkdirAll(stateDirectory, 0700); err != nil {
			panic(err)
		}
		if err := os.Chmod(stateDirectory, 0700); err != nil {
			panic(err)
		}
	}
	dependencies.CookieJar = newCookieJar(stateDirectory)
	dependencies.Keychain = newKeychain(cmd.Context(), stateDirectory, interactive, serviceName)
	dependencies.AppStore = appstore.NewAppStore(appstore.Args{
		AuthenticationProgress: newStageReporter(),
		CookieJar:              dependencies.CookieJar,
		OperatingSystem:        dependencies.OS,
		Keychain:               dependencies.Keychain,
		Machine:                dependencies.Machine,
	})
}
