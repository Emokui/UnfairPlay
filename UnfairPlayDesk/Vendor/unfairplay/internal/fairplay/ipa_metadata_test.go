package fairplay

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func TestInspectIPAFileMetadataAndSelectors(t *testing.T) {
	info := map[string]any{
		"CFBundleDisplayName": "Synthetic App", "CFBundleName": "Fallback",
		"CFBundleIdentifier": "example.synthetic", "CFBundleShortVersionString": "2.4", "CFBundleVersion": "27",
		"CFBundleIcons": map[string]any{"CFBundlePrimaryIcon": map[string]any{"CFBundleIconFiles": []string{"AppIcon60x60"}}},
	}
	encoded, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	image := make([]byte, 8204)
	copy(image, thinHeader(true, true))
	file := filepath.Join(t.TempDir(), "Synthetic.ipa")
	icon := []byte("synthetic-icon")
	members := map[string][]byte{
		"Payload/Test.app/Info.plist":                                        encoded,
		"Payload/Test.app/Test":                                              image,
		"Payload/Test.app/AppIcon60x60@2x.png":                               icon,
		"Payload/Test.app/Watch/Watch.app/Info.plist":                        []byte("unrelated nested plist"),
		"Payload/Test.app/SC_Info/Test.sinf":                                 currentLayoutSINF(SINFSelector{User: 1, Key: 2}),
		"Payload/Test.app/Frameworks/Example.framework/SC_Info/Example.sinf": currentLayoutSINF(SINFSelector{User: 1, Key: 3}),
	}
	writeMultiSINFArchive(t, file, members)
	result := InspectIPAFile(file)
	if result.Status != "encrypted" || result.Name != "Synthetic App" || result.BundleID != "example.synthetic" || result.Version != "2.4" || result.Build != "27" {
		t.Fatalf("unexpected display metadata: %+v", result)
	}
	if result.Bytes == 0 || !bytes.Equal(result.Icon, icon) {
		t.Fatal("file size or icon missing")
	}
	if !result.SelectorScanComplete || len(result.SelectorIDs) != 2 || result.SelectorIDs[0] != "00000001:00000002" || result.SelectorIDs[1] != "00000001:00000003" {
		t.Fatalf("selector coverage: %v, %v", result.SelectorIDs, result.SelectorScanComplete)
	}
	members["Payload/Test.app/SC_Info/Broken.sinf"] = []byte("broken")
	writeMultiSINFArchive(t, file, members)
	partial := InspectIPAFile(file)
	if partial.SelectorScanComplete || len(partial.SelectorIDs) != 2 || partial.Status != "encrypted" {
		t.Fatal("partial license scan misreported")
	}
}

func TestInspectIPAFileMetadataLimitsAndInvalidArchive(t *testing.T) {
	file := filepath.Join(t.TempDir(), "Synthetic.ipa")
	writeMultiSINFArchive(t, file, map[string][]byte{
		"Payload/Test.app/Info.plist": bytes.Repeat([]byte("x"), (4<<20)+1),
		"Payload/Test.app/Test":       thinHeader(false, false),
	})
	result := InspectIPAFile(file)
	if result.Name != "" || result.Status != "clear" || result.SelectorScanComplete {
		t.Fatal("oversized plist affected marker scan")
	}
	missing := InspectIPAFile(filepath.Join(t.TempDir(), "missing.ipa"))
	if missing.Status != "unknown" || missing.SelectorScanComplete {
		t.Fatal("missing archive accepted")
	}
}

func TestInspectIPAFileArtworkFallback(t *testing.T) {
	info := map[string]any{"CFBundleName": "Synthetic", "CFBundleIconFiles": []string{"AppIcon"}}
	encoded, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "Synthetic.ipa")
	artwork := []byte("synthetic artwork")
	members := map[string][]byte{
		"Payload/Test.app/Info.plist": encoded,
		"Payload/Test.app/Test":       thinHeader(false, false),
		"iTunesArtwork":               artwork,
	}
	writeMultiSINFArchive(t, filename, members)
	if result := InspectIPAFile(filename); !bytes.Equal(result.Icon, artwork) {
		t.Fatal("root artwork was not used")
	}
	members["Payload/Test.app/AppIcon.png"] = []byte("synthetic app icon")
	writeMultiSINFArchive(t, filename, members)
	if result := InspectIPAFile(filename); !bytes.Equal(result.Icon, members["Payload/Test.app/AppIcon.png"]) {
		t.Fatal("app icon priority changed")
	}
	delete(members, "Payload/Test.app/AppIcon.png")
	members["iTunesArtwork"] = bytes.Repeat([]byte("x"), (512<<10)+1)
	writeMultiSINFArchive(t, filename, members)
	if result := InspectIPAFile(filename); len(result.Icon) != 0 {
		t.Fatal("oversized artwork accepted")
	}
}

type metadataTestReader struct {
	io.Reader
	closeErr error
}

func (r metadataTestReader) Close() error { return r.closeErr }

func TestIPAMetadataBytesPropagatesReadAndCloseErrors(t *testing.T) {
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	entry, err := writer.Create("metadata")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(encoded.Bytes()), int64(encoded.Len()))
	if err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("synthetic close failure")
	body := []byte("four")
	reader.RegisterDecompressor(zip.Deflate, func(io.Reader) io.ReadCloser {
		return metadataTestReader{Reader: bytes.NewReader(body), closeErr: closeErr}
	})
	if _, err := ipaMetadataBytes(reader.File[0], 8); !errors.Is(err, closeErr) {
		t.Fatalf("close error lost: %v", err)
	}
	body = []byte("too large")
	if _, err := ipaMetadataBytes(reader.File[0], 8); !errors.Is(err, zip.ErrFormat) || !errors.Is(err, closeErr) {
		t.Fatalf("read or close error lost: %v", err)
	}
}
