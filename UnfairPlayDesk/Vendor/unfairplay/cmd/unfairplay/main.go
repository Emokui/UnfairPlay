package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DrWhax/unfairplay/internal/fairplay"
	"github.com/DrWhax/unfairplay/internal/recovery"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "unfairplay",
		Short:         "Recover native Mac FairPlay enrollment and decrypt personalized IPAs",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}
	root.AddCommand(newSetupCommand(), newCollectCommand(), newRecoverCommand(), newDecryptCommand(), newConvertIPAMacOSCommand(), newVerifyCommand(), newDoctorCommand(), newProfileCommand())
	return root
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writePrivateFile(path string, value []byte) (returnErr error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".unfairplay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
			if published {
				_ = os.Remove(path)
			}
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	published = true
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Remove(temporaryPath)
}

func newCollectCommand() *cobra.Command {
	var options fairplay.EnrollmentCollectOptions
	command := &cobra.Command{
		Use:   "collect",
		Short: "Collect one private native Mac App Store enrollment bundle",
		RunE: func(_ *cobra.Command, _ []string) error {
			manifest, err := fairplay.CollectEnrollment(options)
			if err != nil {
				return err
			}
			return printJSON(map[string]any{
				"success": true, "capture": options.OutputPath, "build": manifest.FairPlay.Build,
				"support": manifest.FairPlay.Status, "selector": manifest.App.SelectorID,
				"files": len(manifest.Files),
			})
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.AppPath, "app", "", "Native App Store-installed .app path")
	flags.StringVar(&options.InstalledExecutablePath, "installed-executable-path", "", "Original absolute executable path for an archived app")
	flags.StringVar(&options.IPAPath, "ipa", "", "Matching personalized encrypted IPA")
	flags.StringVar(&options.OutputPath, "output", "", "New private capture directory")
	flags.StringVar(&options.FairPlaydPath, "fairplayd", "", "fairplayd Mach-O (defaults to the system CoreFP framework)")
	flags.StringVar(&options.SystemStatePath, "system-state", "", "System SC Info directory")
	flags.StringVar(&options.SharedStatePath, "shared-state", "", "Shared SC Info directory")
	flags.StringVar(&options.ADIPath, "adi-state", "", "Native ADI state directory")
	flags.StringVar(&options.MACAddressPath, "iomac-file", "", "Private six-byte IOMACAddress file")
	flags.StringVar(&options.HardwareInterface, "interface", "en0", "Built-in IORegistry network interface")
	flags.StringVar(&options.ProductVersion, "product-version", "", "Archived source macOS product version")
	flags.StringVar(&options.BuildVersion, "build-version", "", "Archived source macOS build version")
	_ = command.MarkFlagRequired("app")
	_ = command.MarkFlagRequired("output")
	return command
}

type recoverOptions struct {
	VerifyOnly         bool
	Reference          string
	SelectionMaxBlocks int
	Capture            string
	Output             string
}

func newRecoverCommand() *cobra.Command {
	var options recoverOptions
	command := &cobra.Command{
		Use:   "recover",
		Short: "Recover and validate a private enrollment model from a capture",
		RunE: func(command *cobra.Command, _ []string) error {
			return recoverEnrollment(command.Context(), options)
		},
	}
	command.Flags().StringVar(&options.Reference, "reference-binary", "", "Override hash-matched fairplayd reference code")
	command.Flags().IntVar(&options.SelectionMaxBlocks, "selection-max-blocks", 2_000_000, "Selection execution limit (1..20000000)")
	command.Flags().StringVar(&options.Capture, "capture", "", "Private capture directory")
	command.Flags().StringVar(&options.Output, "output", "", "New private recovery directory")
	_ = command.MarkFlagRequired("capture")
	_ = command.MarkFlagRequired("output")
	return command
}

func recoveryReference(options recoverOptions, manifest fairplay.EnrollmentCaptureManifest) (string, string, error) {
	if options.Reference != "" {
		return options.Reference, "explicit-binary", nil
	}
	if manifest.FairPlay.EvaluatorSHA256 == "" || !strings.EqualFold(manifest.FairPlay.EvaluatorSHA256, manifest.FairPlayd.SHA256) {
		return "", "embedded-profile", nil
	}
	relative := filepath.FromSlash(manifest.FairPlayd.Path)
	clean := filepath.Clean(relative)
	if relative == "" || filepath.IsAbs(relative) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("capture contains an unsafe fairplayd path")
	}
	return filepath.Join(options.Capture, clean), "captured-exact-binary", nil
}

type enrollmentRecoveryOutcome struct {
	Summary   map[string]any
	ModelPath string
}

func recoverEnrollmentResult(ctx context.Context, options recoverOptions) (enrollmentRecoveryOutcome, error) {
	var outcome enrollmentRecoveryOutcome
	manifest, err := fairplay.LoadEnrollmentCapture(options.Capture, true)
	if err != nil {
		return outcome, fmt.Errorf("validate capture: %w", err)
	}
	if manifest.IPA == nil {
		return outcome, errors.New("capture has no matching personalized IPA")
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(options.Capture, manifest)
	if err != nil {
		return outcome, fmt.Errorf("normalize capture: %w", err)
	}
	if !canonical.RecoveryReady {
		return outcome, errors.New("canonical enrollment input is not recovery-ready")
	}
	referencePath, referenceSource, err := recoveryReference(options, manifest)
	if err != nil {
		return outcome, err
	}
	if err := os.Mkdir(options.Output, 0o700); err != nil {
		return outcome, err
	}
	canonicalDocument, err := fairplay.MarshalCanonicalEnrollmentInput(canonical)
	if err != nil {
		return outcome, err
	}
	if err := writePrivateFile(filepath.Join(options.Output, "canonical-input.json"), append(canonicalDocument, '\n')); err != nil {
		return outcome, err
	}
	executablePath := manifest.App.ExecutablePath
	if executablePath == "" {
		executablePath = filepath.Join("/Applications", manifest.App.Executable+".app", manifest.App.Executable)
	}
	var recovered recovery.Result
	selectedProfile := ""
	var recoveryErrors []error
	for _, inputProfile := range []struct {
		name     string
		expanded bool
	}{{"minimal-current-sinf", false}, {"expanded-capture", true}} {
		select {
		case <-ctx.Done():
			return outcome, ctx.Err()
		default:
		}
		mappings, stateFiles := canonical.RuntimeFileMappings(inputProfile.expanded)
		if stateFiles == 0 {
			recoveryErrors = append(recoveryErrors, fmt.Errorf("%s has no FairPlay state", inputProfile.name))
			continue
		}
		mappings = append([]string{"/" + manifest.App.Executable + "=" + canonical.PrivateExecutablePath()}, mappings...)
		recovered, err = recovery.Recover(recovery.Options{
			FileMappings: mappings, HardwarePath: canonical.PrivateHardwarePath(), ExecutablePath: executablePath,
			ReferencePath: referencePath, SelectionMaxBlocks: options.SelectionMaxBlocks,
		})
		if err == nil {
			selectedProfile = inputProfile.name
			break
		}
		recoveryErrors = append(recoveryErrors, fmt.Errorf("%s: %w", inputProfile.name, err))
	}
	if selectedProfile == "" {
		return outcome, fmt.Errorf("derive enrollment: %w", errors.Join(recoveryErrors...))
	}
	defer clear(recovered.EnrollmentModel)
	candidate := filepath.Join(options.Output, "fairplay-enrollment.candidate.bin")
	if err := writePrivateFile(candidate, recovered.EnrollmentModel); err != nil {
		return outcome, err
	}
	ipa := filepath.Join(options.Capture, filepath.FromSlash(manifest.IPA.Path))
	decrypted := filepath.Join(options.Output, "App.decrypted.ipa")
	decryptionReport := filepath.Join(options.Output, "App.decrypted.json")
	validate := fairplay.DecryptIPA
	if options.VerifyOnly {
		validate = fairplay.VerifyIPA
	}
	result, err := validate(fairplay.DecryptOptions{
		InputPath: ipa, OutputPath: decrypted, ReportPath: decryptionReport, ModelPath: candidate, Progress: printOperationProgress,
	})
	if err != nil {
		return outcome, fmt.Errorf("validate recovered enrollment: %w", err)
	}
	enrollment := filepath.Join(options.Output, "fairplay-enrollment.bin")
	if err := os.Rename(candidate, enrollment); err != nil {
		return outcome, err
	}
	summary := map[string]any{
		"schema": "unfairplay-enrollment-recovery-v1", "success": true,
		"selector": manifest.App.SelectorID, "fairplayd_sha256": manifest.FairPlayd.SHA256,
		"fairplayd_status": manifest.FairPlay.Status, "validation_basis": manifest.FairPlay.ValidationBasis,
		"evaluator_profile": manifest.FairPlay.EvaluatorProfile, "evaluator_source_sha256": manifest.FairPlay.EvaluatorSHA256,
		"portable_semantic_evaluator": manifest.FairPlay.EvaluatorSHA256 != "" && manifest.FairPlay.EvaluatorSHA256 != manifest.FairPlayd.SHA256,
		"canonical_contract":          canonical.Contract, "canonical_input_sha256": canonical.FingerprintSHA256,
		"enrollment_model": enrollment, "decrypted_ipa": decrypted,
		"plaintext_verified": result.PlaintextVerified, "encrypted_images": result.EncryptedImages,
		"decrypted_pages": result.DecryptedPages, "input_profile": selectedProfile,
		"recovery_iterations": recovered.Iterations, "recovery_state_sha256": recovered.StateSHA256,
		"exact_extracted_block_hits": recovered.ExtractedBlockHits,
		"promotion_gate":             "complete-sinf-and-ipa-validation",
		"reference_code_source":      referenceSource,
	}
	summary["decrypted_ipa_sha256"] = result.OutputSHA256
	if options.VerifyOnly {
		delete(summary, "decrypted_ipa")
		delete(summary, "decrypted_ipa_sha256")
		summary["validation_mode"] = "all-encrypted-images-in-memory"
		summary["plaintext_verified"] = result.PlaintextVerified
	}
	document, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return outcome, err
	}
	report := filepath.Join(options.Output, "recovery-report.json")
	if err := writePrivateFile(report, append(document, '\n')); err != nil {
		return outcome, err
	}
	return enrollmentRecoveryOutcome{Summary: summary, ModelPath: enrollment}, nil
}

func recoverEnrollment(ctx context.Context, options recoverOptions) error {
	outcome, err := recoverEnrollmentResult(ctx, options)
	if err != nil {
		return err
	}
	return printJSON(outcome.Summary)
}

type decryptOptions struct {
	Input, Output, Report, Model string
	Force                        bool
}

func newDecryptCommand() *cobra.Command {
	var options decryptOptions
	command := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a personalized IPA with a recovered enrollment model",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(options.Input), ".ipa") {
				return errors.New("input must be an IPA")
			}
			modelPath, err := selectedModelPath(options.Model)
			if err != nil {
				return err
			}
			stem := strings.TrimSuffix(options.Input, filepath.Ext(options.Input))
			if options.Output == "" {
				options.Output = stem + ".decrypted.ipa"
			}
			if options.Report == "" {
				options.Report = stem + ".decrypted.json"
			}
			result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
				InputPath: options.Input, OutputPath: options.Output, ReportPath: options.Report,
				ModelPath: modelPath, Force: options.Force, Progress: printOperationProgress,
			})
			if err != nil {
				return err
			}
			return printJSON(result)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.Input, "input", "", "Personalized encrypted IPA")
	flags.StringVar(&options.Output, "output", "", "Decrypted analysis IPA path")
	flags.StringVar(&options.Report, "report", "", "Private decryption report path")
	flags.StringVar(&options.Model, "model", "", "Private enrollment model file or directory (defaults to saved models)")
	flags.BoolVar(&options.Force, "force", false, "Replace existing output and report")
	_ = command.MarkFlagRequired("input")
	return command
}

type convertIPAMacOSOptions struct {
	Input, Output, Credential, Model string
	Force                            bool
}

func newConvertIPAMacOSCommand() *cobra.Command {
	var options convertIPAMacOSOptions
	command := &cobra.Command{
		Use:   "convert-ipa-macos",
		Short: "Convert a personalized encrypted IPA for macOS FairPlay",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(options.Input), ".ipa") {
				return errors.New("input must be an IPA")
			}
			if options.Credential != "" && options.Model != "" {
				return errors.New("pass either --credential or --model, not both")
			}
			if options.Credential == "" {
				modelPath, err := selectedModelPath(options.Model)
				if err != nil {
					return err
				}
				options.Model = modelPath
			}
			stem := strings.TrimSuffix(options.Input, filepath.Ext(options.Input))
			if options.Output == "" {
				options.Output = stem + ".macos.ipa"
			}
			result, err := fairplay.PrepareMacOSIPA(fairplay.MacOSPrepareOptions{
				InputPath: options.Input, OutputPath: options.Output,
				CredentialPath: options.Credential, ModelPath: options.Model, Force: options.Force,
			})
			if err != nil {
				return err
			}
			return printJSON(result)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.Input, "input", "", "Personalized encrypted IPA")
	flags.StringVar(&options.Output, "output", "", "Converted encrypted IPA path")
	flags.StringVar(&options.Model, "model", "", "Private version-2 enrollment model or directory (defaults to saved models)")
	flags.StringVar(&options.Credential, "credential", "", "Private 16-byte account credential instead of a model")
	flags.BoolVar(&options.Force, "force", false, "Replace existing output")
	_ = command.MarkFlagRequired("input")
	return command
}

func verificationSummary(result fairplay.DecryptResult) map[string]any {
	summary := map[string]any{
		"schema": "unfairplay-model-verification-v2", "success": true,
		"plaintext_verified": result.PlaintextVerified,
		"encrypted_images":   result.EncryptedImages, "decrypted_pages": result.DecryptedPages,
		"logical_key_sha256_by_sinf": result.LogicalKeySHA256BySINF,
		"plaintext_retained":         false,
	}
	if result.OutputSHA256 != "" {
		summary["decrypted_ipa_sha256"] = result.OutputSHA256
	}
	if result.LogicalKeySHA256 != "" {
		summary["schema"] = "unfairplay-model-verification-v1"
		summary["logical_key_sha256"] = result.LogicalKeySHA256
	}
	return summary
}

func newVerifyCommand() *cobra.Command {
	var inputPath, modelPath string
	command := &cobra.Command{
		Use:   "verify",
		Short: "Validate an enrollment model against an IPA without retaining plaintext",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(inputPath), ".ipa") {
				return errors.New("input must be an IPA")
			}
			selectedModel, err := selectedModelPath(modelPath)
			if err != nil {
				return err
			}
			result, err := fairplay.VerifyIPA(fairplay.DecryptOptions{InputPath: inputPath, ModelPath: selectedModel, Progress: printOperationProgress})
			if err != nil {
				return err
			}
			return printJSON(verificationSummary(result))
		},
	}
	command.Flags().StringVar(&inputPath, "input", "", "Personalized encrypted IPA")
	command.Flags().StringVar(&modelPath, "model", "", "Private enrollment model file or directory (defaults to saved models)")
	_ = command.MarkFlagRequired("input")
	return command
}

func newDoctorCommand() *cobra.Command {
	var capture, ipa, model, reportPath string
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose capture, SINF, model, and evaluator support",
		RunE: func(_ *cobra.Command, _ []string) error {
			report := fairplay.DoctorFairPlay(capture, ipa, model)
			if reportPath != "" {
				if err := fairplay.WriteDoctorReport(reportPath, report); err != nil {
					return err
				}
			}
			if err := printJSON(report); err != nil {
				return err
			}
			if len(report.Errors) != 0 {
				return errors.New("diagnostic checks failed")
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&capture, "capture", "", "Private enrollment capture directory")
	flags.StringVar(&ipa, "ipa", "", "Personalized encrypted IPA")
	flags.StringVar(&model, "model", "", "Private enrollment model file or directory")
	flags.StringVar(&reportPath, "report", "", "New private JSON diagnostic report")
	return command
}

func newProfileCommand() *cobra.Command {
	var binaryPath, outputPath, recoveryProfilePath string
	command := &cobra.Command{
		Use:   "profile",
		Short: "Inspect an arm64e fairplayd without executing it",
		RunE: func(_ *cobra.Command, _ []string) error {
			profile, err := fairplay.InspectFairPlayBinaryProfile(binaryPath)
			if err != nil {
				return err
			}
			if recoveryProfilePath != "" {
				encoded, summary, err := fairplay.BuildFairPlayRecoveryCodeProfile(binaryPath)
				if err != nil {
					return err
				}
				defer clear(encoded)
				if err := writePrivateFile(recoveryProfilePath, encoded); err != nil {
					return err
				}
				profile.RecoveryCodeProfile = &summary
			}
			if outputPath != "" {
				document, err := json.MarshalIndent(profile, "", "  ")
				if err != nil {
					return err
				}
				if err := writePrivateFile(outputPath, append(document, '\n')); err != nil {
					return err
				}
			}
			return printJSON(profile)
		},
	}
	command.Flags().StringVar(&binaryPath, "binary", "", "arm64e or universal fairplayd Mach-O")
	command.Flags().StringVar(&outputPath, "output", "", "New private JSON profile")
	command.Flags().StringVar(&recoveryProfilePath, "recovery-profile-output", "", "New hash-bound recovery code profile")
	_ = command.MarkFlagRequired("binary")
	return command
}
