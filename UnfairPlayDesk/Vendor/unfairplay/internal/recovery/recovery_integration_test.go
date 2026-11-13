package recovery_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DrWhax/unfairplay/internal/fairplay"
	"github.com/DrWhax/unfairplay/internal/recovery"
)

// Private capture inputs are optional and are never stored in the repository.
func TestRecoveryReproducibleLocalCapture(t *testing.T) {
	capture := os.Getenv("UNFAIRPLAY_TEST_CAPTURE")
	reference := os.Getenv("UNFAIRPLAY_TEST_REFERENCE")
	if capture == "" || reference == "" {
		t.Skip("local capture/reference not configured")
	}
	manifest, err := fairplay.LoadEnrollmentCapture(capture, true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(capture, manifest)
	if err != nil {
		t.Fatal(err)
	}
	mappings, stateFiles := canonical.RuntimeFileMappings(false)
	if stateFiles == 0 {
		t.Fatal("capture has no FairPlay state")
	}
	mappings = append([]string{"/" + manifest.App.Executable + "=" + canonical.PrivateExecutablePath()}, mappings...)
	executablePath := manifest.App.ExecutablePath
	if executablePath == "" {
		executablePath = filepath.Join("/Applications", manifest.App.Executable+".app", manifest.App.Executable)
	}
	options := recovery.Options{
		FileMappings: mappings, HardwarePath: canonical.PrivateHardwarePath(),
		ExecutablePath: executablePath, ReferencePath: reference,
		SelectionMaxBlocks: 20_000_000,
	}
	first, err := recovery.Recover(options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.EnrollmentModel)
	second, err := recovery.Recover(options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.EnrollmentModel)
	if first.StateSHA256 != second.StateSHA256 || first.Iterations != second.Iterations ||
		first.ExtractedBlockHits != second.ExtractedBlockHits || !bytes.Equal(first.EnrollmentModel, second.EnrollmentModel) {
		t.Fatal("repeated recovery in one process was not deterministic")
	}
	if manifest.IPA == nil {
		t.Fatal("capture has no validation IPA")
	}
	directory := t.TempDir()
	modelPath := filepath.Join(directory, "model.bin")
	if err := os.WriteFile(modelPath, second.EnrollmentModel, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath: filepath.Join(capture, manifest.IPA.Path), ModelPath: modelPath,
		OutputPath: filepath.Join(directory, "out.ipa"), ReportPath: filepath.Join(directory, "out.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EncryptedImages == 0 || result.DecryptedPages == 0 {
		t.Fatal("no encrypted images were validated")
	}
}
