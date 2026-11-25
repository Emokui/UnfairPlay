//go:build !windows

package cachelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

func canonicalLockPath(path string) string {
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

func verifyNoSymlinkAncestor(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("lock directory is not an ordinary directory: %s", current)
			}
			resolved, evalErr := filepath.EvalSymlinks(current)
			if evalErr != nil {
				return evalErr
			}
			if canonicalLockPath(current) != canonicalLockPath(resolved) {
				return fmt.Errorf("lock directory contains a symlink component: %s", path)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func ensureLockDirectory(dir string) error {
	if err := verifyNoSymlinkAncestor(dir); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("lock directory is not an ordinary directory: %s", dir)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return verifyNoSymlinkAncestor(dir)
}

func openLockFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("lock path is not a regular file: %s", path)
	}
	return file, nil
}

func tryLock(file *os.File) (bool, error) {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
