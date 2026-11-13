package recovery

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"fmt"
	"os"
)

// addReferencePages adds data from an exact-hash fairplayd arm64e slice. The
// binary is parsed as data and is never loaded or executed.
func addReferencePages(value *model, path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128*1024*1024 {
		return fmt.Errorf("reference binary must be a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	profile, err := executionProfileForModel(value)
	if err != nil {
		return err
	}
	if sha256.Sum256(data) != profile.binaryHash {
		return fmt.Errorf("reference binary SHA256 mismatch")
	}
	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer file.Close()
	text := file.Segment("__TEXT")
	if text == nil || text.Filesz == 0 || text.Filesz > 32*1024*1024 || text.Addr%pageSize != 0 {
		return fmt.Errorf("invalid reference text segment")
	}
	payload, err := text.Data()
	if err != nil {
		return err
	}
	for offset := uint64(0); offset < uint64(len(payload)); offset += pageSize {
		address := text.Addr + offset
		if value.pages[address] != nil {
			continue
		}
		page := make([]byte, pageSize)
		copy(page, payload[offset:min(offset+pageSize, uint64(len(payload)))])
		value.pages[address] = page
	}
	extracted, err := loadCompact26A428SafeExtractedBlocks()
	if err != nil {
		return fmt.Errorf("load exact-build extracted blocks: %w", err)
	}
	value.exactExtractedBlocks = extracted
	value.allowDestinationPages = true
	return nil
}
