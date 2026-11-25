package cachelock

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

// Acquire serializes cold cache preparation across CLI processes.
func Acquire(ctx context.Context, path string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureLockDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	for {
		locked, err := tryLock(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("lock component cache: %w", err)
		}
		if locked {
			return func() { file.Close() }, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
