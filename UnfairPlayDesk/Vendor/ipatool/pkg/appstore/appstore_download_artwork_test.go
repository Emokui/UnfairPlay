package appstore

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
	"howett.net/plist"
)

func TestDownloadArtworkAndIncludeInIPA(t *testing.T) {
	requests := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = io.WriteString(w, "artwork bytes")
	}))
	defer server.Close()

	store := &appstore{httpClient: newDownloadTestClient(), os: operatingsystem.New()}
	for _, url := range []string{"", server.URL} {
		data, err := store.downloadArtwork(context.Background(), url)
		if err != nil {
			t.Fatal(err)
		}

		if url == "" && (len(data) != 0 || requests != 0) {
			t.Fatal("artwork was downloaded without a URL")
		}

		if url != "" && string(data) != "artwork bytes" {
			t.Fatal("artwork missing")
		}

		path := filepath.Join(t.TempDir(), "source.zip")

		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}

		writer := zip.NewWriter(file)
		if _, err := writer.Create("Payload/App.app/"); err != nil {
			t.Fatal(err)
		}

		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}

		if err := file.Close(); err != nil {
			t.Fatal(err)
		}

		if err := store.applyPatches(downloadItemResult{Metadata: map[string]interface{}{}}, Account{}, path, path+".ipa", data, false); err != nil {
			t.Fatal(err)
		}

		reader, err := zip.OpenReader(path + ".ipa")
		if err != nil {
			t.Fatal(err)
		}

		found := false

		for _, entry := range reader.File {
			if entry.Name != "iTunesArtwork" {
				continue
			}

			found = true

			r, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}

			actual, err := io.ReadAll(r)
			r.Close()

			if err != nil || string(actual) != "artwork bytes" {
				t.Fatalf("artwork = %q; %v", actual, err)
			}
		}

		reader.Close()

		if found != (url != "") {
			t.Fatal("incorrect artwork presence")
		}
	}
}

func TestDownloadArtworkRejectsFailedResponse(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	store := &appstore{httpClient: newDownloadTestClient()}
	if _, err := store.downloadArtwork(context.Background(), server.URL); err == nil {
		t.Fatal("accepted error page as artwork")
	}

	if data, err := store.downloadArtwork(context.Background(), ""); err != nil || len(data) != 0 {
		t.Fatal("missing artwork URL should be skipped")
	}
}

func TestDownloadArtworkRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 64<<10)
		for written := 0; written <= maxArtworkBytes; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	store := &appstore{httpClient: newDownloadTestClient()}
	if _, err := store.downloadArtwork(context.Background(), server.URL); err == nil {
		t.Fatal("accepted oversized artwork response")
	}
}

func TestFinalizationPreservesIPAWhenOptionalArtworkFails(t *testing.T) {
	for _, rewriteFails := range []bool{false, true} {
		name := "optional artwork"
		if rewriteFails {
			name = "failed archive rewrite"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			tmpPath := filepath.Join(root, "output.ipa.tmp")
			file, err := os.Create(tmpPath)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			image, err := writer.Create("iTunesArtwork")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = io.WriteString(image, "existing artwork"); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}

			artworkReady := make(chan artworkResult, 1)
			artworkReady <- artworkResult{err: context.DeadlineExceeded}
			target := filepath.Join(root, "output.ipa")
			if rewriteFails {
				target = filepath.Join(root, "missing-folder", "output.ipa")
			}
			store := &appstore{os: operatingsystem.New()}
			err = store.finishDownloadedIPA(DownloadInput{}, downloadItemResult{}, "", tmpPath, target, artworkReady)
			if (err != nil) != rewriteFails {
				t.Fatalf("unexpected finalization result: %v", err)
			}
			if _, err := os.Stat(tmpPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary package was not removed: %v", err)
			}
			if rewriteFails {
				return
			}
			archive, err := zip.OpenReader(target)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			data, err := fs.ReadFile(archive, "iTunesArtwork")
			if err != nil || string(data) != "existing artwork" {
				t.Fatalf("original artwork was lost: %q, %v", data, err)
			}
		})
	}
}

func TestWriteMetadataClonesCallerMapAndHandlesNil(t *testing.T) {
	store := &appstore{}
	account := Account{Email: "user@example.invalid"}

	for _, test := range []struct {
		name     string
		metadata map[string]interface{}
	}{
		{name: "nil metadata", metadata: nil},
		{name: "caller metadata", metadata: map[string]interface{}{"apple-id": "original@example.invalid", "bundleShortVersionString": "1.2.3"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "metadata.zip")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			writer := zip.NewWriter(file)
			if err := store.writeMetadata(test.metadata, account, writer); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			if test.metadata != nil && test.metadata["apple-id"] != "original@example.invalid" {
				t.Fatalf("caller metadata map was mutated: %v", test.metadata)
			}
			if test.metadata != nil {
				if _, exists := test.metadata["userName"]; exists {
					t.Fatalf("caller metadata map gained userName: %v", test.metadata)
				}
			}

			archive, err := zip.OpenReader(path)
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			raw, err := fs.ReadFile(archive, "iTunesMetadata.plist")
			if err != nil {
				t.Fatal(err)
			}
			var decoded map[string]interface{}
			if _, err := plist.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded["apple-id"] != account.Email || decoded["userName"] != account.Email {
				t.Fatalf("unexpected written metadata: %v", decoded)
			}
		})
	}
}
