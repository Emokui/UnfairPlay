package cmd

import (
	"fmt"
	stdos "os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

func canonicalSystemPath(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "darwin" {
		for _, prefix := range []string{"/var", "/tmp", "/etc"} {
			if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
				return "/private" + cleaned
			}
		}
	}
	return cleaned
}

func rejectSymlinkPath(path string) error {
	cleaned := filepath.Clean(path)
	current := cleaned
	for {
		info, err := stdos.Lstat(current)
		if err == nil {
			if info.Mode()&stdos.ModeSymlink != 0 {
				return fmt.Errorf("state path must not be a symlink: %s", current)
			}
			resolved, evalErr := filepath.EvalSymlinks(current)
			if evalErr != nil {
				return evalErr
			}
			if canonicalSystemPath(current) != canonicalSystemPath(resolved) {
				return fmt.Errorf("state path contains a symlink component: %s", path)
			}
			return nil
		}
		if !stdos.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

// prepareStateDirectory resolves and migrates session storage before it is opened.
func prepareStateDirectory(os operatingsystem.OperatingSystem, homeDirectory string) (string, error) {
	legacyDirectory := filepath.Join(homeDirectory, ConfigDirectoryName)
	stateDirectory := legacyDirectory

	for _, variable := range []string{"XDG_STATE_HOME", "XDG_DATA_HOME"} {
		if base := os.Getenv(variable); filepath.IsAbs(base) {
			stateDirectory = filepath.Join(base, "ipatool")

			break
		}
	}

	if err := rejectSymlinkPath(legacyDirectory); err != nil {
		return "", err
	}
	if stateDirectory != legacyDirectory {
		if err := rejectSymlinkPath(stateDirectory); err != nil {
			return "", err
		}
	}

	info, err := os.Stat(legacyDirectory)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("could not read legacy state directory metadata: %w", err)
	}

	if err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("legacy state path is not a directory: %s", legacyDirectory)
		}
		// Never merge sessions or move a directory into itself. Keeping the legacy
		// directory also preserves authentication when migration is unavailable.
		relative, err := filepath.Rel(legacyDirectory, stateDirectory)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return legacyDirectory, nil
		}

		if _, err := os.Stat(stateDirectory); err == nil || !os.IsNotExist(err) {
			return legacyDirectory, nil
		}

		if err := os.MkdirAll(filepath.Dir(stateDirectory), 0700); err != nil {
			return legacyDirectory, nil
		}
		// Rename keeps cookies and encrypted credentials together, with their
		// existing permissions. Cross-filesystem moves fall back to legacy storage.
		if err := os.Rename(legacyDirectory, stateDirectory); err != nil {
			return legacyDirectory, nil
		}

		return stateDirectory, nil
	}

	if err := os.MkdirAll(stateDirectory, 0700); err != nil {
		return "", fmt.Errorf("failed to create state directory: %w", err)
	}
	if err := rejectSymlinkPath(stateDirectory); err != nil {
		return "", err
	}

	return stateDirectory, nil
}
