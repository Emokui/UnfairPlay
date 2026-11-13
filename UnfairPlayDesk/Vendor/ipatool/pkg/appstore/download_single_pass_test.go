package appstore

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"howett.net/plist"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func downloadZIPFixture(t testing.TB) (string, downloadItemResult) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "source.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	payload := bytes.Repeat([]byte("synthetic executable payload"), 4096)
	if _, ok := t.(*testing.B); ok {
		payload = make([]byte, 4<<20)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
	}
	info, err := plist.Marshal(map[string]any{"CFBundleExecutable": "Test", "CFBundleIdentifier": "test.synthetic"}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"Payload/Test.app/Info.plist": info, "Payload/Test.app/Test": payload} {
		target, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = target.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return p, downloadItemResult{Metadata: map[string]any{"bundleShortVersionString": "1"}, Sinfs: []Sinf{{Data: []byte("synthetic-sinf")}}}
}
func zipMemberContents(t testing.TB, p string) map[string][]byte {
	t.Helper()
	r, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out := map[string][]byte{}
	for _, f := range r.File {
		if _, ok := out[f.Name]; ok {
			t.Fatal("duplicate member", f.Name)
		}
		reader, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name], err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
func TestSinglePassDownloadMatchesTwoPassPersonalization(t *testing.T) {
	src, item := downloadZIPFixture(t)
	store := &appstore{os: operatingsystem.New()}
	account := Account{Email: "test@example.invalid"}
	combined := filepath.Join(t.TempDir(), "combined.ipa")
	old := filepath.Join(t.TempDir(), "two-pass.ipa")
	if err := store.applyPatches(item, account, src, combined, []byte("artwork")); err != nil {
		t.Fatal(err)
	}
	bare := item
	bare.Sinfs = nil
	if err := store.applyPatches(bare, account, src, old, []byte("artwork")); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplicateSinf(ReplicateSinfInput{PackagePath: old, Sinfs: item.Sinfs}); err != nil {
		t.Fatal(err)
	}
	a, b := zipMemberContents(t, combined), zipMemberContents(t, old)
	if len(a) != len(b) {
		t.Fatal("member count changed")
	}
	for name, data := range a {
		if !bytes.Equal(data, b[name]) {
			t.Fatal("different payload", name)
		}
	}
	if !bytes.Equal(a["Payload/Test.app/SC_Info/Test.sinf"], []byte("synthetic-sinf")) {
		t.Fatal("missing personalized license")
	}
	original, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	result, err := zip.OpenReader(combined)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	for _, before := range original.File {
		for _, after := range result.File {
			if before.Name == after.Name {
				x, _ := before.OpenRaw()
				y, _ := after.OpenRaw()
				xb, _ := io.ReadAll(x)
				yb, _ := io.ReadAll(y)
				if !bytes.Equal(xb, yb) {
					t.Fatal("recompressed unchanged member")
				}
			}
		}
	}
}

func BenchmarkDownloadPersonalization(b *testing.B) {
	for _, combined := range []bool{false, true} {
		name := "two-pass"
		if combined {
			name = "single-pass"
		}
		b.Run(name, func(b *testing.B) {
			src, item := downloadZIPFixture(b)
			store := &appstore{os: operatingsystem.New()}
			account := Account{Email: "test@example.invalid"}
			output := filepath.Join(b.TempDir(), "result.ipa")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if combined {
					if err := store.applyPatches(item, account, src, output, nil); err != nil {
						b.Fatal(err)
					}
				} else {
					bare := item
					bare.Sinfs = nil
					if err := store.applyPatches(bare, account, src, output, nil); err != nil {
						b.Fatal(err)
					}
					if err := store.ReplicateSinf(ReplicateSinfInput{PackagePath: output, Sinfs: item.Sinfs}); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
