package assets

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type countingKernelReader struct {
	*bytes.Reader
	reads   int
	largest int
}

func (r *countingKernelReader) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	if len(p) > r.largest {
		r.largest = len(p)
	}
	return r.Reader.ReadAt(p, off)
}
func TestKernelEntryUsesOnePayloadRead(t *testing.T) {
	data := make([]byte, 2<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("kernel")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	source := &countingKernelReader{Reader: bytes.NewReader(archive.Bytes())}
	zr, err := zip.NewReader(source, int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	if _, err = f.DataOffset(); err != nil {
		t.Fatal(err)
	}
	source.reads = 0
	source.largest = 0
	got, err := readKernelEntry(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || source.reads != 2 || source.largest != int(f.CompressedSize64) {
		t.Fatalf("payload reads=%d largest=%d", source.reads, source.largest)
	}
	f.CRC32 ^= 1
	if _, err := readKernelEntry(f); !errors.Is(err, zip.ErrChecksum) {
		t.Fatalf("checksum error=%v", err)
	}
	f.CompressedSize64 = kernelCacheCompressedSize + 1
	if _, err := readKernelEntry(f); err == nil {
		t.Fatal("accepted oversized member")
	}
}

// Opt-in public-asset preparation; no Apple account or credentials are used.
func TestPreparePublicAuthenticationAssets(t *testing.T) {
	source := os.Getenv("DESK_PUBLIC_FRAMEWORK_DIR")
	if source == "" {
		t.Skip("public asset preparation is opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now()
	remote, err := openRemoteFile(ctx, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(remote, remote.size)
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err = extractFairPlayKext(archive, filepath.Join(dst, "FairPlayIOKit")); err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte)
	for _, spec := range requiredFiles {
		dir := source
		if spec.name == "FairPlayIOKit" {
			dir = dst
		}
		files[spec.name], err = os.ReadFile(filepath.Join(dir, spec.name))
		if err != nil {
			t.Fatal(err)
		}
	}
	bundle := bundleFrom(files)
	if err = validate(bundle); err != nil {
		t.Fatal(err)
	}
	dir, err := cacheDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err = writeCache(dir, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err = readCache(dir); err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel download, extraction and full cache validation: %s", time.Since(started))
}
