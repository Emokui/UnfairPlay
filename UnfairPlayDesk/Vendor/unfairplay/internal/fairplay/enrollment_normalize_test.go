package fairplay

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCanonicalSIDBClassifiesKnownGeometry(t *testing.T) {
	for _, test := range []struct {
		bytes, source int
	}{{630, 192}, {642, 192}, {993, 224}, {1003, 224}} {
		t.Run(fmt.Sprintf("%d", test.bytes), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "SC Info.sidb")
			data := make([]byte, test.bytes)
			binary.BigEndian.PutUint32(data[:4], 0x0007000b)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			sidb, err := canonicalSIDB(CanonicalEnrollmentFile{
				CapturePath: "state/fpsd-sc-info/SC Info.sidb", Bytes: int64(len(data)), localPath: path,
			})
			if err != nil {
				t.Fatal(err)
			}
			if sidb.Version != 0x0007000b || sidb.Format != "macos-sidb-v7000b" || sidb.ExpectedSourceBytes != test.source {
				t.Fatalf("unexpected SIDB classification: %#v", sidb)
			}
		})
	}
}

func TestCanonicalInputFingerprintExcludesLocalPaths(t *testing.T) {
	base := CanonicalEnrollmentInput{
		Schema: CanonicalEnrollmentInputSchema, Contract: "macos-current-sinf-v1",
		SelectorID: "synthetic:00000002",
		Executable: CanonicalEnrollmentFile{Role: "installed-executable", CapturePath: "app/executable", SHA256: "01", localPath: "/private/one"},
	}
	left, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Executable.localPath = "/different/private/path"
	right, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatal("canonical fingerprint depends on a private local path")
	}
	base.Executable.SHA256 = "02"
	changed, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if changed == left {
		t.Fatal("canonical fingerprint ignored exported file identity")
	}
}

func TestCanonicalRuntimeMappingsUseNormalizedRoles(t *testing.T) {
	input := CanonicalEnrollmentInput{
		ExecutableName:    "App",
		InstalledSINFFile: CanonicalEnrollmentFile{VirtualPath: "App.sinf", localPath: "/capture/App.sinf"},
		SUPFs: []CanonicalSUPF{
			{File: CanonicalEnrollmentFile{VirtualPath: "App.v5.supf", localPath: "/capture/App.v5.supf"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "App.v6.supf", localPath: "/capture/App.v6.supf"}},
		},
		SIDBs: []CanonicalSIDB{{File: CanonicalEnrollmentFile{
			Role: "fpsd-state", VirtualPath: "/var/db/fpsd/SC Info/SC Info.sidb", localPath: "/capture/SC Info.sidb",
		}}},
		StateFiles: []CanonicalEnrollmentFile{{
			Role: "adi-state", VirtualPath: "/var/db/fpsd/adi/adi.pb", localPath: "/capture/adi.pb",
		}},
	}
	minimal, states := input.RuntimeFileMappings(false)
	wantMinimal := []string{
		"/var/db/fpsd/SC Info/SC Info.sidb=/capture/SC Info.sidb",
		"App.sinf=/capture/App.sinf",
		"App.v5.supf=/capture/App.v5.supf",
	}
	if states != 1 || !slices.Equal(minimal, wantMinimal) {
		t.Fatalf("minimal mappings = %#v, state files = %d", minimal, states)
	}
	expanded, states := input.RuntimeFileMappings(true)
	wantExpanded := []string{
		"/var/db/fpsd/SC Info/SC Info.sidb=/capture/SC Info.sidb",
		"/var/db/fpsd/adi/adi.pb=/capture/adi.pb",
		"App.sinf=/capture/App.sinf",
		"App.v5.supf=/capture/App.v5.supf",
		"App.v6.supf=/capture/App.v6.supf",
	}
	if states != 2 || !slices.Equal(expanded, wantExpanded) {
		t.Fatalf("expanded mappings = %#v, state files = %d", expanded, states)
	}
}
