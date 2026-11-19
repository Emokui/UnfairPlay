//go:build (darwin && !ios) || linux

package unicorn

import (
	"context"
	"fmt"

	"github.com/ebitengine/purego"
)

// The verified library stays loaded for this CLI process. Engines remain independent.
var libraryGate = make(chan struct{}, 1)
var sharedLibrary library

func openLibrary(ctx context.Context) (library, error) {
	select {
	case libraryGate <- struct{}{}:
	case <-ctx.Done():
		return library{}, ctx.Err()
	}
	defer func() { <-libraryGate }()

	if err := ctx.Err(); err != nil {
		return library{}, err
	}
	if sharedLibrary.handle != 0 {
		return sharedLibrary, nil
	}

	paths, err := cachedRuntimePaths(ctx)
	if err != nil {
		return library{}, err
	}

	if err := ctx.Err(); err != nil {
		return library{}, fmt.Errorf("load Unicorn library: %w", err)
	}

	handle, err := purego.Dlopen(paths.library, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return library{}, fmt.Errorf("%s: %w", paths.library, err)
	}

	sharedLibrary = library{handle: handle, close: func() error { return nil }}
	return sharedLibrary, nil
}
