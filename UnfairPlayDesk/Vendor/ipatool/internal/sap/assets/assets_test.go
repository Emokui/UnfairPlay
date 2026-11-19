package assets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCacheFile(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedSize int
		wantErr      string
	}{
		{name: "exact size", data: []byte("12345678"), expectedSize: 8},
		{name: "too short", data: []byte("1234"), expectedSize: 8, wantErr: "has size 4, expected 8"},
		{name: "too large", data: bytes.Repeat([]byte{1}, 64), expectedSize: 8, wantErr: "has size 64, expected 8"},
		{name: "invalid expected size", expectedSize: -1, wantErr: "invalid expected size"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "asset")
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := readCacheFile(path, test.expectedSize)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("readCacheFile() error = %v", err)
				}

				if !bytes.Equal(got, test.data) {
					t.Fatalf("readCacheFile() = %q, want %q", got, test.data)
				}

				return
			}

			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("readCacheFile() error = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestVerifiedDigestRequiresExactLoaderVerifiedSlice(t *testing.T) {
	spec := requiredFiles[0]
	unverified := Bundle{AppleMediaServices: make([]byte, spec.size)}
	if _, ok := unverified.VerifiedDigest(spec.name, unverified.AppleMediaServices); ok {
		t.Fatal("unverified bundle must not report a verified digest")
	}

	verified := markBundleVerified(unverified)
	digest, ok := verified.VerifiedDigest(spec.name, verified.AppleMediaServices)
	if !ok || digest != spec.digest {
		t.Fatalf("expected pinned digest for verified slice, got ok=%v", ok)
	}

	cloned := bytes.Clone(verified.AppleMediaServices)
	if _, ok := verified.VerifiedDigest(spec.name, cloned); ok {
		t.Fatal("distinct backing slice must not bypass SHA-256 computation")
	}
}
