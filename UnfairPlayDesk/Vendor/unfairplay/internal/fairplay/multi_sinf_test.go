package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func multiSINFImage(t *testing.T, logical [16]byte, word uint32) ([]byte, []byte, []byte) {
	t.Helper()
	blob, _ := signedAuditFixture(t, pageBytes, pageBytes, 12, 2)
	clear(blob[:pageBytes])
	le := func(at int, value uint32) { binary.LittleEndian.PutUint32(blob[at:], value) }
	le(0, mhMagic64)
	le(4, cpuTypeARM64)
	le(12, 2)
	le(16, 2)
	le(20, 40)
	le(32, lcEncryptionInfo64)
	le(36, 24)
	le(40, pageBytes)
	le(44, pageBytes)
	le(48, 1)
	le(56, lcCodeSignature)
	le(60, 16)
	le(64, 2*pageBytes)
	le(68, uint32(len(blob)-2*pageBytes))

	plain := make([]byte, pageBytes)
	for offset := 0; offset < len(plain); offset += 4 {
		binary.LittleEndian.PutUint32(plain[offset:], word)
	}
	var record [32]byte
	for index := range record {
		record[index] = byte(index + 1)
	}
	deriver := newPageKeyDeriver(appMaskFromLogicalKey(logical))
	key := deriver.pageKey(record[:16], pageBytes)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, record[16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plain)
	directory := blob[2*pageBytes+20:]
	for slot := 0; slot < 2; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[44+slot*32:], hash)
	}
	supf := make([]byte, 60)
	supf[0] = 5
	be := func(at int, value uint32) { binary.BigEndian.PutUint32(supf[at:], value) }
	be(4, 52)
	be(8, 1)
	be(12, 44)
	be(16, cpuTypeARM64)
	be(24, 1)
	copy(supf[28:], record[:])
	return blob, supf, plain
}

func writeMultiSINFArchive(t *testing.T, name string, members map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	order := []string{
		"Payload/Test.app/Test",
		"Payload/Test.app/SC_Info/Test.sinf",
		"Payload/Test.app/SC_Info/Test.supf",
		"Payload/Test.app/keep.txt",
		"Payload/Test.app/PlugIns/Widget.appex/Test",
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.sinf",
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.supf",
	}
	for _, member := range order {
		data, ok := members[member]
		if !ok {
			continue
		}
		writer, err := archive.Create(member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptMultipleSINFs(t *testing.T) {
	directory := t.TempDir()
	mainPath := "Payload/Test.app/Test"
	widgetPath := "Payload/Test.app/PlugIns/Widget.appex/Test"
	mainFixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	widgetFixture := syntheticCurrentSINFFixture(t, 42, 8, 88, [16]byte{9, 8, 7})
	mainBlob, mainSUPF, mainPlain := multiSINFImage(t, mainFixture.logical, 0xd503201f)
	widgetBlob, widgetSUPF, widgetPlain := multiSINFImage(t, widgetFixture.logical, 0xd65f03c0)
	members := map[string][]byte{
		mainPath: mainBlob, adjacentSINF(mainPath): mainFixture.sinf,
		"Payload/Test.app/SC_Info/Test.supf": mainSUPF,
		widgetPath:                           widgetBlob, adjacentSINF(widgetPath): widgetFixture.sinf,
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.supf": widgetSUPF,
		"Payload/Test.app/keep.txt":                               []byte("unchanged"),
	}
	input := filepath.Join(directory, "App.ipa")
	writeMultiSINFArchive(t, input, members)
	models := filepath.Join(directory, "models")
	if err := os.Mkdir(models, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, selector := range map[string]SINFSelector{
		"main.bin": mainFixture.selector, "widget.bin": widgetFixture.selector,
	} {
		if err := os.WriteFile(filepath.Join(models, name), selectorBoundModelPack(t, selector), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, reportPath := filepath.Join(directory, "out.ipa"), filepath.Join(directory, "out.json")
	result, err := DecryptIPA(DecryptOptions{
		InputPath: input, OutputPath: output, ReportPath: reportPath, ModelPath: models,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EncryptedImages != 2 || result.DecryptedPages != 2 || result.LogicalKeySHA256 != "" || len(result.LogicalKeySHA256BySINF) != 2 {
		t.Fatalf("incorrect multi-license result: %+v", result)
	}
	if result.LogicalKeySHA256BySINF[adjacentSINF(mainPath)] == result.LogicalKeySHA256BySINF[adjacentSINF(widgetPath)] {
		t.Fatal("different logical keys were conflated")
	}

	before, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var progress []OperationProgress
	verified, err := VerifyIPA(DecryptOptions{InputPath: input, ModelPath: models, Progress: func(event OperationProgress) { progress = append(progress, event) }})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || verified.OutputPath != "" || verified.ReportPath != "" || verified.OutputSHA256 != "" {
		t.Fatal("verification wrote an output artifact")
	}
	if verified.EncryptedImages != result.EncryptedImages || verified.DecryptedPages != result.DecryptedPages || len(verified.LogicalKeySHA256BySINF) != 2 {
		t.Fatalf("verification skipped images: %+v", verified)
	}
	if verified.PlaintextVerified {
		t.Fatal("legacy structural fixture was described as hash-verified")
	}
	if len(progress) == 0 || progress[len(progress)-1].Completed != 2 || progress[len(progress)-1].Phase != "complete" {
		t.Fatal("missing complete verification progress")
	}

	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		got, err := zipBytes(file)
		if err != nil {
			t.Fatal(err)
		}
		want := members[file.Name]
		if file.Name == mainPath || file.Name == widgetPath {
			want = append([]byte(nil), want...)
			binary.LittleEndian.PutUint32(want[48:], 0)
			plain := mainPlain
			if file.Name == widgetPath {
				plain = widgetPlain
			}
			copy(want[pageBytes:2*pageBytes], plain)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("wrong bytes for %s", file.Name)
		}
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report decryptionReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Complete || len(report.Licenses) != 2 || len(report.Images) != 2 {
		t.Fatalf("incomplete report: %+v", report)
	}
	for _, image := range report.Images {
		if image.SINFMember != adjacentSINF(image.Member) {
			t.Fatalf("wrong SINF for %s", image.Member)
		}
	}
	doctor := DoctorFairPlay("", input, models)
	if !doctor.DecryptReady || len(doctor.CompatibleModelsBySINF) != 2 {
		t.Fatalf("doctor rejected valid multi-license IPA: %v", doctor.Errors)
	}
}

func TestMultipleSINFsFailBeforePublishing(t *testing.T) {
	directory := t.TempDir()
	mainPath := "Payload/Test.app/Test"
	widgetPath := "Payload/Test.app/PlugIns/Widget.appex/Test"
	fixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	mainBlob, mainSUPF, _ := multiSINFImage(t, fixture.logical, 0xd503201f)
	widgetBlob, widgetSUPF, _ := multiSINFImage(t, fixture.logical, 0xd65f03c0)
	members := map[string][]byte{
		mainPath:                             mainBlob,
		"Payload/Test.app/SC_Info/Test.supf": mainSUPF,
		widgetPath:                           widgetBlob,
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.supf": widgetSUPF,
	}
	input := filepath.Join(directory, "App.ipa")
	writeMultiSINFArchive(t, input, members)
	output, report := filepath.Join(directory, "out.ipa"), filepath.Join(directory, "out.json")
	if err := os.WriteFile(output, []byte("existing output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("existing report"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := DecryptIPA(DecryptOptions{InputPath: input, OutputPath: output, ReportPath: report, Force: true})
	if err == nil {
		t.Fatal("accepted an encrypted executable without an adjacent SINF")
	}
	if _, err := VerifyIPA(DecryptOptions{InputPath: input}); err == nil {
		t.Fatal("verification accepted missing SINF")
	}

	for path, want := range map[string]string{output: "existing output", report: "existing report"} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("published partial output at %s", path)
		}
	}
}

func TestSINFNameFallsBackToContainingApp(t *testing.T) {
	main := "Payload/Test.app/SC_Info/Test.sinf"
	child := "Payload/Test.app/PlugIns/Widget.appex/Widget"
	got, err := sinfName(map[string]bool{main: true}, child)
	if err != nil || got != main {
		t.Fatalf("containing SINF=%q err=%v", got, err)
	}
	_, err = sinfName(map[string]bool{
		main: true, "Payload/Test.app/SC_Info/Other.sinf": true,
	}, child)
	if err == nil {
		t.Fatal("accepted an ambiguous containing license")
	}
}

func TestAdjacentSINFTopLevel(t *testing.T) {
	if got := adjacentSINF("App"); got != "SC_Info/App.sinf" {
		t.Fatalf("top-level license path: %s", got)
	}
}
