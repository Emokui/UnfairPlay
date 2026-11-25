package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sessionProfile string
var sessionProfilePattern = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func validateSessionProfile(profile string) error {
	if profile != "" && !sessionProfilePattern.MatchString(profile) {
		return fmt.Errorf("session profile must be a UUID")
	}
	return nil
}

// A profile isolates both the keychain namespace and on-disk cookie/file-backend
// storage. The legacy service is never read or overwritten by a named profile.
func sessionNamespace(home, profile string) (string, string, error) {
	if err := validateSessionProfile(profile); err != nil {
		return "", "", err
	}
	if profile == "" {
		return "", KeychainServiceName, nil
	}
	normalized := strings.ToLower(profile)
	return filepath.Join(home, "Library", "Application Support", "UnfairPlayDesk", "Sessions", normalized), KeychainServiceName + "." + normalized, nil
}

func prepareProfileSessionDirectory(home, profile string) (string, string, error) {
	stateDirectory, serviceName, err := sessionNamespace(home, profile)
	if err != nil {
		return "", "", err
	}
	if home == "" {
		return "", "", fmt.Errorf("home directory is empty")
	}
	segments := []string{"Library", "Application Support", "UnfairPlayDesk", "Sessions", strings.ToLower(profile)}
	current := home
	for _, segment := range segments {
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", "", fmt.Errorf("session path is not an ordinary directory: %s", current)
			}
			continue
		}
		if !os.IsNotExist(statErr) {
			return "", "", statErr
		}
		if err := os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
			return "", "", err
		}
		info, statErr = os.Lstat(current)
		if statErr != nil {
			return "", "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", "", fmt.Errorf("session path is not an ordinary directory: %s", current)
		}
	}
	if err := os.Chmod(stateDirectory, 0700); err != nil {
		return "", "", err
	}
	return stateDirectory, serviceName, nil
}

func removeSessionCookies(stateDirectory string) error {
	if stateDirectory == "" {
		return nil
	}
	info, err := os.Lstat(stateDirectory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("session path is not an ordinary directory: %s", stateDirectory)
	}
	for _, name := range []string{CookieJarFileName, CookieJarFileName + ".lock"} {
		target := filepath.Join(stateDirectory, name)
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove session cookie state: %w", err)
		}
	}
	return nil
}

func removeProfileCookies(stateDirectory, profile string) error {
	if profile == "" {
		return nil
	}
	return removeSessionCookies(stateDirectory)
}
