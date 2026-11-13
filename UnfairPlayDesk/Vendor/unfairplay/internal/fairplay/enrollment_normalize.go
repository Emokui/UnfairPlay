package fairplay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const CanonicalEnrollmentInputSchema = "unfairplay-canonical-enrollment-v1"

type CanonicalEnrollmentFile struct {
	Role        string `json:"role"`
	CapturePath string `json:"capture_path"`
	VirtualPath string `json:"virtual_path,omitempty"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
	localPath   string
}

type CanonicalSUPFArchitecture struct {
	CPUType    uint32 `json:"cpu_type"`
	CPUSubtype uint32 `json:"cpu_subtype"`
	Pages      int    `json:"pages"`
}

type CanonicalSUPF struct {
	File          CanonicalEnrollmentFile     `json:"file"`
	Variant       uint8                       `json:"variant"`
	Architectures []CanonicalSUPFArchitecture `json:"architectures"`
}

type CanonicalSIDB struct {
	File                CanonicalEnrollmentFile `json:"file"`
	Version             uint32                  `json:"version"`
	Format              string                  `json:"format"`
	ExpectedSourceBytes int                     `json:"expected_source_bytes,omitempty"`
}

type CanonicalEnrollmentInput struct {
	Schema            string                    `json:"schema"`
	Contract          string                    `json:"contract"`
	FingerprintSHA256 string                    `json:"fingerprint_sha256"`
	Selector          SINFSelector              `json:"selector"`
	SelectorID        string                    `json:"selector_id"`
	ExecutableName    string                    `json:"executable_name"`
	InstalledSINF     SINFDiagnostic            `json:"installed_sinf"`
	InstalledSINFFile CanonicalEnrollmentFile   `json:"installed_sinf_file"`
	TargetSINF        *SINFDiagnostic           `json:"target_sinf,omitempty"`
	Executable        CanonicalEnrollmentFile   `json:"executable"`
	Hardware          CanonicalEnrollmentFile   `json:"hardware"`
	SUPFs             []CanonicalSUPF           `json:"supfs"`
	SIDBs             []CanonicalSIDB           `json:"sidbs"`
	AuxiliaryLicenses []CanonicalEnrollmentFile `json:"auxiliary_licenses,omitempty"`
	StateFiles        []CanonicalEnrollmentFile `json:"state_files,omitempty"`
	RecoveryReady     bool                      `json:"recovery_ready"`
	Warnings          []string                  `json:"warnings,omitempty"`
}

func canonicalFile(capturePath string, file EnrollmentCaptureFile, role, virtualPath string) (CanonicalEnrollmentFile, error) {
	full, err := captureFilePath(capturePath, file.Path)
	if err != nil {
		return CanonicalEnrollmentFile{}, err
	}
	return CanonicalEnrollmentFile{
		Role: role, CapturePath: filepath.ToSlash(file.Path), VirtualPath: virtualPath,
		Bytes: file.Bytes, SHA256: file.SHA256, localPath: full,
	}, nil
}

func canonicalSIDB(file CanonicalEnrollmentFile) (CanonicalSIDB, error) {
	data, err := os.ReadFile(file.localPath)
	if err != nil {
		return CanonicalSIDB{}, err
	}
	if len(data) < 4 {
		return CanonicalSIDB{}, fmt.Errorf("SIDB %s is truncated", file.CapturePath)
	}
	version := binary.BigEndian.Uint32(data[:4])
	result := CanonicalSIDB{File: file, Version: version}
	if version == 0x0007000b {
		result.Format = "macos-sidb-v7000b"
		switch len(data) {
		case 630, 642:
			result.ExpectedSourceBytes = 192
		case 993, 1003:
			result.ExpectedSourceBytes = 224
		}
	} else {
		result.Format = "unknown"
	}
	return result, nil
}

func canonicalSUPF(file CanonicalEnrollmentFile) (CanonicalSUPF, error) {
	data, err := os.ReadFile(file.localPath)
	if err != nil {
		return CanonicalSUPF{}, err
	}
	parsed, err := parseSUPF(data)
	if err != nil {
		return CanonicalSUPF{}, fmt.Errorf("parse %s: %w", file.CapturePath, err)
	}
	result := CanonicalSUPF{File: file, Variant: data[0]}
	for _, architecture := range parsed.architectures {
		result.Architectures = append(result.Architectures, CanonicalSUPFArchitecture{
			CPUType: architecture.cpuType, CPUSubtype: architecture.cpuSubtype, Pages: len(architecture.records),
		})
	}
	return result, nil
}

func canonicalSINF(file CanonicalEnrollmentFile) (SINFDiagnostic, error) {
	data, err := os.ReadFile(file.localPath)
	if err != nil {
		return SINFDiagnostic{}, err
	}
	result, err := InspectSINF(data)
	if err != nil {
		return result, fmt.Errorf("inspect %s: %w", file.CapturePath, err)
	}
	result.Path = file.CapturePath
	return result, nil
}

func canonicalInputFingerprint(input CanonicalEnrollmentInput) (string, error) {
	input.FingerprintSHA256 = ""
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func (input CanonicalEnrollmentInput) PrivateExecutablePath() string {
	return input.Executable.localPath
}
func (input CanonicalEnrollmentInput) PrivateHardwarePath() string { return input.Hardware.localPath }

func (input CanonicalEnrollmentInput) RuntimeFileMappings(expanded bool) ([]string, int) {
	var mappings []string
	stateFiles := 0
	appendFile := func(file CanonicalEnrollmentFile, state bool) {
		if file.VirtualPath == "" || file.localPath == "" {
			return
		}
		mappings = append(mappings, file.VirtualPath+"="+file.localPath)
		if state {
			stateFiles++
		}
	}
	appendFile(input.InstalledSINFFile, false)
	for _, value := range input.SUPFs {
		name := filepath.Base(value.File.VirtualPath)
		if expanded || name == input.ExecutableName+".supf" || name == input.ExecutableName+".v5.supf" {
			appendFile(value.File, false)
		}
	}
	if expanded {
		for _, value := range input.AuxiliaryLicenses {
			appendFile(value, false)
		}
	}
	for _, value := range input.SIDBs {
		appendFile(value.File, true)
	}
	for _, value := range input.StateFiles {
		name := filepath.Base(value.VirtualPath)
		if expanded || value.Role == "fpsd-state" && strings.HasPrefix(name, "SC Info.") {
			appendFile(value, true)
		}
	}
	sort.Strings(mappings)
	return mappings, stateFiles
}

func NormalizeEnrollmentCapture(capturePath string, manifest EnrollmentCaptureManifest) (CanonicalEnrollmentInput, error) {
	result := CanonicalEnrollmentInput{
		Schema: CanonicalEnrollmentInputSchema, Contract: "macos-current-sinf-v1",
		Selector: manifest.App.Selector, SelectorID: manifest.App.SelectorID, ExecutableName: manifest.App.Executable,
	}
	files := make(map[string]EnrollmentCaptureFile, len(manifest.Files))
	for _, file := range manifest.Files {
		files[filepath.ToSlash(file.Path)] = file
	}
	executableDescriptor, ok := files["app/executable"]
	if !ok {
		return result, fmt.Errorf("capture has no installed executable")
	}
	var err error
	result.Executable, err = canonicalFile(capturePath, executableDescriptor, "installed-executable", "/"+manifest.App.Executable)
	if err != nil {
		return result, err
	}
	hardwareDescriptor, ok := files[filepath.ToSlash(manifest.HardwareMAC.Path)]
	if !ok || hardwareDescriptor.SHA256 != manifest.HardwareMAC.SHA256 || hardwareDescriptor.Bytes != manifest.HardwareMAC.Bytes {
		return result, fmt.Errorf("capture has no verified hardware identity descriptor")
	}
	result.Hardware, err = canonicalFile(capturePath, hardwareDescriptor, "hardware-iomac", "")
	if err != nil {
		return result, err
	}
	hardware, err := os.ReadFile(result.Hardware.localPath)
	if err != nil {
		return result, err
	}
	if len(hardware) != 6 {
		return result, fmt.Errorf("canonical hardware identity must contain six bytes")
	}
	clear(hardware)
	installedDescriptor, ok := files[filepath.ToSlash(manifest.App.SINFPath)]
	if !ok {
		return result, fmt.Errorf("capture has no installed SINF descriptor")
	}
	installedFile, err := canonicalFile(capturePath, installedDescriptor, "installed-sinf", filepath.Base(manifest.App.SINFPath))
	if err != nil {
		return result, err
	}
	result.InstalledSINF, err = canonicalSINF(installedFile)
	if err != nil {
		return result, err
	}
	if result.InstalledSINF.Selector != manifest.App.Selector || result.InstalledSINF.SelectorID != manifest.App.SelectorID {
		return result, fmt.Errorf("installed SINF selector does not match capture manifest")
	}
	if !result.InstalledSINF.CurrentLayout {
		return result, fmt.Errorf("installed SINF does not use the current layout")
	}
	result.InstalledSINFFile = installedFile
	if manifest.App.TargetSINFPath != "" {
		targetDescriptor, exists := files[filepath.ToSlash(manifest.App.TargetSINFPath)]
		if !exists {
			return result, fmt.Errorf("capture has no target SINF descriptor")
		}
		targetFile, fileErr := canonicalFile(capturePath, targetDescriptor, "target-sinf", "")
		if fileErr != nil {
			return result, fileErr
		}
		target, inspectErr := canonicalSINF(targetFile)
		if inspectErr != nil {
			return result, inspectErr
		}
		if target.Selector != manifest.App.Selector {
			return result, fmt.Errorf("target SINF selector does not match capture manifest")
		}
		result.TargetSINF = &target
	}
	for captured, descriptor := range files {
		var role, virtualPath string
		switch {
		case strings.HasPrefix(captured, "app/SC_Info/"):
			name := strings.TrimPrefix(captured, "app/SC_Info/")
			if captured == filepath.ToSlash(manifest.App.SINFPath) {
				continue
			}
			role, virtualPath = "license-auxiliary", name
		case strings.HasPrefix(captured, "state/fpsd-sc-info/"):
			name := strings.TrimPrefix(captured, "state/fpsd-sc-info/")
			role, virtualPath = "fpsd-state", "/var/db/fpsd/SC Info/"+name
		case strings.HasPrefix(captured, "state/shared-sc-info/"):
			name := strings.TrimPrefix(captured, "state/shared-sc-info/")
			role, virtualPath = "shared-state", "/Users/Shared/SC Info/"+name
		case strings.HasPrefix(captured, "state/adi/"):
			name := strings.TrimPrefix(captured, "state/adi/")
			role, virtualPath = "adi-state", "/var/db/fpsd/adi/"+name
		default:
			continue
		}
		file, fileErr := canonicalFile(capturePath, descriptor, role, virtualPath)
		if fileErr != nil {
			return result, fileErr
		}
		lower := strings.ToLower(filepath.Base(captured))
		switch {
		case strings.HasSuffix(lower, ".supf"):
			supf, parseErr := canonicalSUPF(file)
			if parseErr != nil {
				return result, parseErr
			}
			result.SUPFs = append(result.SUPFs, supf)
		case lower == "sc info.sidb":
			sidb, parseErr := canonicalSIDB(file)
			if parseErr != nil {
				return result, parseErr
			}
			result.SIDBs = append(result.SIDBs, sidb)
		case role == "license-auxiliary":
			result.AuxiliaryLicenses = append(result.AuxiliaryLicenses, file)
		default:
			result.StateFiles = append(result.StateFiles, file)
		}
	}
	sort.Slice(result.SUPFs, func(left, right int) bool {
		return result.SUPFs[left].File.VirtualPath < result.SUPFs[right].File.VirtualPath
	})
	sort.Slice(result.SIDBs, func(left, right int) bool {
		return result.SIDBs[left].File.VirtualPath < result.SIDBs[right].File.VirtualPath
	})
	sort.Slice(result.AuxiliaryLicenses, func(left, right int) bool {
		return result.AuxiliaryLicenses[left].VirtualPath < result.AuxiliaryLicenses[right].VirtualPath
	})
	sort.Slice(result.StateFiles, func(left, right int) bool {
		return result.StateFiles[left].VirtualPath < result.StateFiles[right].VirtualPath
	})
	if len(result.SUPFs) == 0 {
		return result, fmt.Errorf("canonical input has no valid SUPF")
	}
	if len(result.SIDBs) == 0 {
		return result, fmt.Errorf("canonical input has no SIDB state")
	}
	for _, sidb := range result.SIDBs {
		if sidb.Format == "unknown" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("SIDB %s has unrecognized version %#08x", sidb.File.CapturePath, sidb.Version))
		} else if sidb.ExpectedSourceBytes == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("SIDB %s has an unclassified size", sidb.File.CapturePath))
		}
	}
	result.RecoveryReady = true
	result.FingerprintSHA256, err = canonicalInputFingerprint(result)
	if err != nil {
		return result, err
	}
	return result, nil
}

func MarshalCanonicalEnrollmentInput(input CanonicalEnrollmentInput) ([]byte, error) {
	return json.MarshalIndent(input, "", "  ")
}
