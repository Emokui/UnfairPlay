package appstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxArtworkBytes = 8 << 20

func (t *appstore) downloadArtwork(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		return nil, nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := t.httpClient.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	res, err := t.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected artwork response status: %d", res.StatusCode)
	}

	if res.ContentLength > maxArtworkBytes {
		return nil, fmt.Errorf("artwork exceeds maximum size (%d bytes)", maxArtworkBytes)
	}

	data, err := io.ReadAll(io.LimitReader(res.Body, maxArtworkBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read artwork: %w", err)
	}

	if len(data) > maxArtworkBytes {
		return nil, fmt.Errorf("artwork exceeds maximum size (%d bytes)", maxArtworkBytes)
	}

	if len(data) == 0 {
		return nil, errors.New("artwork response is empty")
	}

	return data, nil
}
