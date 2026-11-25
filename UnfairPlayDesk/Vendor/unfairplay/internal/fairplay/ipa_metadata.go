package fairplay

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"howett.net/plist"
)

// IPAFileInfo contains display metadata and selector hints, never license keys.
// Selector coverage is a preflight hint. Decryption still resolves every license.
type IPAFileInfo struct {
	Path                 string   `json:"path"`
	Status               string   `json:"status"`
	Name                 string   `json:"name,omitempty"`
	BundleID             string   `json:"bundle_id,omitempty"`
	Version              string   `json:"version,omitempty"`
	Build                string   `json:"build,omitempty"`
	Bytes                int64    `json:"bytes"`
	Icon                 []byte   `json:"icon,omitempty"`
	SelectorIDs          []string `json:"selector_ids"`
	SelectorScanComplete bool     `json:"selector_scan_complete"`
}

type ipaIconSet struct {
	Primary struct {
		Files []string `plist:"CFBundleIconFiles"`
	} `plist:"CFBundlePrimaryIcon"`
}

type ipaDisplayInfo struct {
	Name        string     `plist:"CFBundleName"`
	DisplayName string     `plist:"CFBundleDisplayName"`
	BundleID    string     `plist:"CFBundleIdentifier"`
	Version     string     `plist:"CFBundleShortVersionString"`
	Build       string     `plist:"CFBundleVersion"`
	Icon        string     `plist:"CFBundleIconFile"`
	Icons       []string   `plist:"CFBundleIconFiles"`
	PhoneIcons  ipaIconSet `plist:"CFBundleIcons"`
	PadIcons    ipaIconSet `plist:"CFBundleIcons~ipad"`
}

const maxIPAIconBytes = 8 << 20

func ipaMetadataBytes(file *zip.File, maximum uint64) ([]byte, error) {
	if file.UncompressedSize64 > maximum {
		return nil, fmt.Errorf("IPA metadata member exceeds reading limit")
	}
	stream, err := file.Open()
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stream, int64(maximum)+1))
	closeErr := stream.Close()
	if uint64(len(data)) > maximum {
		readErr = errors.Join(readErr, fmt.Errorf("IPA metadata member exceeds reading limit"))
	}
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	return data, nil
}

func InspectIPAFile(filename string) IPAFileInfo {
	result := IPAFileInfo{Path: filename, Status: "unknown", SelectorIDs: []string{}}
	if info, err := os.Stat(filename); err == nil {
		result.Bytes = info.Size()
	}
	archive, err := zip.OpenReader(filename)
	if err != nil {
		return result
	}
	defer archive.Close()
	if encrypted, err := ipaHasEncryptedImages(archive); err == nil {
		result.Status = "clear"
		if encrypted {
			result.Status = "encrypted"
		}
	}
	members := make(map[string]*zip.File, len(archive.File))
	var mainInfo *zip.File
	infoCount := 0
	selectors := make(map[string]bool)
	licenses, complete := 0, true
	for _, file := range archive.File {
		members[file.Name] = file
		parts := strings.Split(file.Name, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			mainInfo = file
			infoCount++
		}
		if !strings.HasPrefix(file.Name, "Payload/") || !strings.Contains(file.Name, "/SC_Info/") || !strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
			continue
		}
		licenses++
		data, err := ipaMetadataBytes(file, 1<<20)
		if err != nil {
			complete = false
			continue
		}
		selector, err := ParseSINFSelector(data)
		if err != nil {
			complete = false
			continue
		}
		selectors[selector.Identifier()] = true
	}
	for selector := range selectors {
		result.SelectorIDs = append(result.SelectorIDs, selector)
	}
	sort.Strings(result.SelectorIDs)
	result.SelectorScanComplete = licenses > 0 && complete
	if infoCount != 1 {
		return result
	}
	data, err := ipaMetadataBytes(mainInfo, 4<<20)
	if err != nil {
		return result
	}
	var info ipaDisplayInfo
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return result
	}
	result.Name = info.DisplayName
	if result.Name == "" {
		result.Name = info.Name
	}
	result.BundleID, result.Version, result.Build = info.BundleID, info.Version, info.Build
	icons := append(info.PhoneIcons.Primary.Files, info.PadIcons.Primary.Files...)
	icons = append(icons, info.Icons...)
	if info.Icon != "" {
		icons = append(icons, info.Icon)
	}
	root := strings.TrimSuffix(mainInfo.Name, "Info.plist")
	for index := len(icons) - 1; index >= 0; index-- {
		base := icons[index]
		if path.Base(base) != base {
			continue
		}
		base = strings.TrimSuffix(base, ".png")
		for _, suffix := range []string{"@3x.png", "@2x.png", ".png", "@2x~ipad.png"} {
			if file := members[root+base+suffix]; file != nil {
				if icon, err := ipaMetadataBytes(file, maxIPAIconBytes); err == nil {
					result.Icon = icon
					return result
				}
			}
		}
	}
	if file := members["iTunesArtwork"]; file != nil {
		if icon, err := ipaMetadataBytes(file, maxIPAIconBytes); err == nil {
			result.Icon = icon
		}
	}
	return result
}
