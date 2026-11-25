package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	stdcookiejar "net/http/cookiejar"
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
var activeStateDirectory string

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

type transientCookieJar struct {
	*stdcookiejar.Jar
}

func (*transientCookieJar) Save() error { return nil }

func openCookieJar(stateDirectory string, loadExisting bool) (http.CookieJar, error) {
	if !loadExisting {
		jar, err := stdcookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("initialize transient cookie jar: %w", err)
		}
		return &transientCookieJar{Jar: jar}, nil
	}
	filename := filepath.Join(stateDirectory, CookieJarFileName)
	if info, err := os.Lstat(filename); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("cookie jar is not a regular file: %s", filename)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect cookie jar: %w", err)
	}
	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: filename,
	})
	if err != nil {
		return nil, fmt.Errorf("load cookie jar: %w", err)
	}
	return &sessionCookieJar{Jar: jar}, nil
}

func newCookieJar(stateDirectory string) http.CookieJar {
	return util.Must(openCookieJar(stateDirectory, true))
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

func passphrasePromptTarget(prompt, fallback string) string {
	if _, after, ok := strings.Cut(prompt, " unlock "); ok {
		if target := strings.TrimSpace(after); target != "" {
			return target
		}
	}
	if trimmed := strings.TrimSpace(prompt); trimmed != "" {
		return trimmed
	}
	return fallback
}

func isAuthRevokeCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.Name() == "revoke" && cmd.Parent() != nil && cmd.Parent().Name() == "auth"
}

func openSessionKeychain(ctx context.Context, stateDirectory string, interactive bool, serviceName string) (keychain.Keychain, error) {
	ring, err := openKeyring(keyring.Config{
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

			path := passphrasePromptTarget(s, stateDirectory)
			password, err := readPrompt(fmt.Sprintf("enter passphrase to unlock %s (this is separate from your Apple ID password): ", path), true)
			if err != nil {
				return "", fmt.Errorf("failed to read password: %w", err)
			}

			return password, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("open credential keyring: %w", err)
	}

	legacy := keychain.New(keychain.Args{
		Keyring: ring,
		Label:   serviceName,
	})
	if sessionProfile == "" {
		return legacy, nil
	}
	if deskSessionFD >= 3 {
		channel := os.NewFile(uintptr(deskSessionFD), "desktop-session")
		if native, ok := ring.(interface{ desktopSessionFD(int) }); ok {
			native.desktopSessionFD(deskSessionFD)
			return keychain.NewDesktopSession(ctx, stateDirectory, serviceName, legacy, channel), nil
		}
		channel.Close()
	}
	return keychain.NewSession(ctx, stateDirectory, serviceName, legacy), nil
}

// newKeychain returns a new keychain instance.
func newKeychain(ctx context.Context, stateDirectory string, interactive bool, serviceName string) keychain.Keychain {
	return util.Must(openSessionKeychain(ctx, stateDirectory, interactive, serviceName))
}

// initWithCommand initializes the dependencies of the command.
func initWithCommand(cmd *cobra.Command) error {
	activeStateDirectory = ""
	verbose := cmd.Flag("verbose").Value.String() == "true"
	interactive, _ := cmd.Context().Value(interactiveKey).(bool)
	format, err := OutputFormatFromString(cmd.Flag("format").Value.String())
	if err != nil {
		return err
	}

	dependencies.Logger = newLogger(format, verbose)
	if cmd.Name() == "mcp" {
		dependencies.Logger = log.NewLogger(log.Args{Verbose: verbose, Writer: zerolog.SyncWriter(os.Stderr)})
	}

	dependencies.OS = operatingsystem.New()
	dependencies.Machine = machine.New(machine.Args{OS: dependencies.OS})
	var stateDirectory string
	serviceName := KeychainServiceName
	if sessionProfile == "" {
		stateDirectory, err = prepareStateDirectory(dependencies.OS, dependencies.Machine.HomeDirectory())
		if err != nil {
			return err
		}
		if info, statErr := os.Lstat(stateDirectory); statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("state directory is not an ordinary directory: %s", stateDirectory)
		}
	} else {
		stateDirectory, serviceName, err = prepareProfileSessionDirectory(dependencies.Machine.HomeDirectory(), sessionProfile)
		if err != nil {
			return err
		}
	}
	activeStateDirectory = stateDirectory
	cookieJar, err := openCookieJar(stateDirectory, !isAuthRevokeCommand(cmd))
	if err != nil {
		return err
	}
	dependencies.CookieJar = cookieJar
	kc, err := openSessionKeychain(cmd.Context(), stateDirectory, interactive, serviceName)
	if err != nil {
		return err
	}
	dependencies.Keychain = kc
	dependencies.AppStore = appstore.NewAppStore(appstore.Args{
		AuthenticationProgress: newStageReporter(),
		CookieJar:              dependencies.CookieJar,
		OperatingSystem:        dependencies.OS,
		Keychain:               dependencies.Keychain,
		Machine:                dependencies.Machine,
	})
	return nil
}
