package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const qaSchema = "unfairplay-private-qa-v1"

type qaManifest struct {
	Schema   string      `json:"schema"`
	Controls []qaControl `json:"controls"`
}

type qaControl struct {
	Name                    string `json:"name"`
	Capture                 string `json:"capture,omitempty"`
	IPA                     string `json:"ipa,omitempty"`
	Model                   string `json:"model,omitempty"`
	Reference               string `json:"reference_binary,omitempty"`
	ExpectedModelSHA256     string `json:"expected_model_sha256,omitempty"`
	ExpectedIPASHA256       string `json:"expected_ipa_sha256,omitempty"`
	ExpectedEvaluatorSHA256 string `json:"expected_evaluator_source_sha256,omitempty"`
	ExpectedReferenceSource string `json:"expected_reference_code_source,omitempty"`
	ExpectedImages          int    `json:"expected_images,omitempty"`
	ExpectedPages           int    `json:"expected_pages,omitempty"`
}

type recoveryResult struct {
	Success               bool   `json:"success"`
	DecryptedIPASHA256    string `json:"decrypted_ipa_sha256"`
	EncryptedImages       int    `json:"encrypted_images"`
	DecryptedPages        int    `json:"decrypted_pages"`
	EvaluatorSourceSHA256 string `json:"evaluator_source_sha256"`
	ReferenceCodeSource   string `json:"reference_code_source"`
	ExtractedBlockHits    int    `json:"exact_extracted_block_hits"`
}

type qaResult struct {
	Name                string `json:"name"`
	Mode                string `json:"mode"`
	ModelSHA256         string `json:"model_sha256"`
	DecryptedIPASHA256  string `json:"decrypted_ipa_sha256"`
	EncryptedImages     int    `json:"encrypted_images"`
	DecryptedPages      int    `json:"decrypted_pages"`
	ReferenceCodeSource string `json:"reference_code_source"`
	ExtractedBlockHits  int    `json:"exact_extracted_block_hits"`
}

func validSHA256(value string) bool {
	if value == "" {
		return true
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validateManifest(manifest qaManifest) error {
	if manifest.Schema != qaSchema || len(manifest.Controls) == 0 {
		return fmt.Errorf("invalid or empty QA manifest")
	}
	seen := make(map[string]bool)
	for _, control := range manifest.Controls {
		recoveryMode := control.Capture != ""
		verifyMode := control.IPA != "" || control.Model != ""
		if control.Name == "" || filepath.Base(control.Name) != control.Name || seen[control.Name] || recoveryMode == verifyMode || verifyMode && (control.IPA == "" || control.Model == "") || !recoveryMode && control.Reference != "" {
			return fmt.Errorf("invalid QA control %q", control.Name)
		}
		seen[control.Name] = true
		for _, value := range []string{control.ExpectedModelSHA256, control.ExpectedIPASHA256, control.ExpectedEvaluatorSHA256} {
			if !validSHA256(value) {
				return fmt.Errorf("control %s has an invalid expected SHA256", control.Name)
			}
		}
		if control.ExpectedImages < 0 || control.ExpectedPages < 0 {
			return fmt.Errorf("control %s has invalid expected counts", control.Name)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func checkControl(control qaControl, result recoveryResult, modelSHA256 string) error {
	if !result.Success || result.EncryptedImages <= 0 || result.DecryptedPages <= 0 {
		return fmt.Errorf("control %s did not complete recovery and decryption", control.Name)
	}
	checks := []struct{ got, want, label string }{
		{modelSHA256, control.ExpectedModelSHA256, "model SHA256"},
		{result.DecryptedIPASHA256, control.ExpectedIPASHA256, "IPA SHA256"},
		{result.EvaluatorSourceSHA256, control.ExpectedEvaluatorSHA256, "evaluator SHA256"},
		{result.ReferenceCodeSource, control.ExpectedReferenceSource, "reference source"},
	}
	for _, check := range checks {
		if check.want != "" && check.got != check.want {
			return fmt.Errorf("control %s %s = %s, want %s", control.Name, check.label, check.got, check.want)
		}
	}
	if control.ExpectedImages != 0 && result.EncryptedImages != control.ExpectedImages {
		return fmt.Errorf("control %s images = %d, want %d", control.Name, result.EncryptedImages, control.ExpectedImages)
	}
	if control.ExpectedPages != 0 && result.DecryptedPages != control.ExpectedPages {
		return fmt.Errorf("control %s pages = %d, want %d", control.Name, result.DecryptedPages, control.ExpectedPages)
	}
	return nil
}

func runControl(ctx context.Context, binary, root string, control qaControl) (qaResult, error) {
	mode := "verify"
	arguments := []string{"verify", "--input", control.IPA, "--model", control.Model}
	modelPath := control.Model
	if control.Capture != "" {
		mode = "recover"
		output := filepath.Join(root, control.Name)
		arguments = []string{"recover", "--capture", control.Capture, "--output", output}
		if control.Reference != "" {
			arguments = append(arguments, "--reference-binary", control.Reference)
		}
		modelPath = filepath.Join(output, "fairplay-enrollment.bin")
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	stdout, err := command.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return qaResult{}, fmt.Errorf("control %s failed: %s", control.Name, strings.TrimSpace(string(exit.Stderr)))
		}
		return qaResult{}, err
	}
	var recovered recoveryResult
	if err := json.Unmarshal(stdout, &recovered); err != nil {
		return qaResult{}, fmt.Errorf("control %s returned invalid JSON: %w", control.Name, err)
	}
	if mode == "verify" {
		recovered.ReferenceCodeSource = "existing-model"
	}
	modelSHA256, err := fileSHA256(modelPath)
	if err != nil {
		return qaResult{}, err
	}
	if err := checkControl(control, recovered, modelSHA256); err != nil {
		return qaResult{}, err
	}
	return qaResult{
		Name: control.Name, Mode: mode, ModelSHA256: modelSHA256, DecryptedIPASHA256: recovered.DecryptedIPASHA256,
		EncryptedImages: recovered.EncryptedImages, DecryptedPages: recovered.DecryptedPages,
		ReferenceCodeSource: recovered.ReferenceCodeSource, ExtractedBlockHits: recovered.ExtractedBlockHits,
	}, nil
}

func run() error {
	binary := flag.String("unfairplay", "", "unfairplay binary to test")
	manifestPath := flag.String("manifest", "", "private QA manifest")
	timeout := flag.Duration("timeout", 30*time.Minute, "timeout for the complete QA matrix")
	flag.Parse()
	if *binary == "" || *manifestPath == "" || *timeout <= 0 {
		return fmt.Errorf("--unfairplay, --manifest, and a positive --timeout are required")
	}
	manifestInfo, err := os.Lstat(*manifestPath)
	if err != nil {
		return err
	}
	if !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("QA manifest must be a private regular file")
	}
	file, err := os.Open(*manifestPath)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var manifest qaManifest
	decodeErr := decoder.Decode(&manifest)
	if decodeErr == nil {
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			decodeErr = fmt.Errorf("QA manifest has trailing data")
		}
	}
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil {
		return fmt.Errorf("read QA manifest: %v %v", decodeErr, closeErr)
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "unfairplay-private-qa-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results := make([]qaResult, 0, len(manifest.Controls))
	for _, control := range manifest.Controls {
		result, err := runControl(ctx, *binary, root, control)
		if err != nil {
			return err
		}
		results = append(results, result)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"schema": qaSchema, "success": true, "controls": results}); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
