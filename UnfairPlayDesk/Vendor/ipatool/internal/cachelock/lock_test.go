package cachelock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireNilContextAndContentionCancellation(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "nested", ".session.lock")
	unlock, err := Acquire(nil, lockPath)
	if err != nil {
		t.Fatalf("acquire with nil context failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, lockPath); !errors.Is(err, context.DeadlineExceeded) {
		unlock()
		t.Fatalf("expected deadline exceeded while contended, got: %v", err)
	}
	unlock()

	unlockAgain, err := Acquire(nil, lockPath)
	if err != nil {
		t.Fatalf("re-acquire after unlock failed: %v", err)
	}
	unlockAgain()
}

func TestAcquireRejectsSymlinkLockAndSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkLock := filepath.Join(root, ".symlink.lock")
	if err := os.Symlink(victim, symlinkLock); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(nil, symlinkLock); err == nil {
		t.Fatal("accepted symlink lock file")
	}

	realDir := filepath.Join(root, "real-dir")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(nil, filepath.Join(linkDir, ".lock")); err == nil {
		t.Fatal("accepted symlink parent directory")
	}
	if _, err := Acquire(nil, filepath.Join(linkDir, "nested-missing", ".lock")); err == nil {
		t.Fatal("accepted symlink ancestor with missing subdirectory")
	}
	if _, err := os.Lstat(filepath.Join(realDir, "nested-missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created subdirectory inside symlink target: %v", err)
	}
	existingSub := filepath.Join(realDir, "nested-existing")
	if err := os.MkdirAll(existingSub, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(nil, filepath.Join(linkDir, "nested-existing", ".lock")); err == nil {
		t.Fatal("accepted symlink ancestor with existing subdirectory")
	}
}
