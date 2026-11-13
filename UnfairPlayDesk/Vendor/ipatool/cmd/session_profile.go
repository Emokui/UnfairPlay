package cmd

import (
	"fmt"
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
