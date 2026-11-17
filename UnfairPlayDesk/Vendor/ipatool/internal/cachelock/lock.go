package cachelock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Acquire serializes cold cache preparation across CLI processes.
func Acquire(ctx context.Context, path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
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
