package recovery

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"sync"
)

// This profile contains only exact-26A428 blocks with a real branch, call, or
// return terminator. Every start already present in the verified profiles was
// used as a boundary and excluded from this fallback.
//
//go:embed profiles/macos26a428-safe-extracted.bin.gz
var compact26A428SafeExtractedCompressed []byte

var (
	compact26A428SafeExtractedOnce   sync.Once
	compact26A428SafeExtractedBlocks map[uint64]compactBlock
	compact26A428SafeExtractedErr    error
)

func loadCompact26A428SafeExtractedBlocks() (map[uint64]compactBlock, error) {
	compact26A428SafeExtractedOnce.Do(func() {
		expected := [32]byte{
			0x40, 0xbe, 0x55, 0xe9, 0x4f, 0x23, 0xdf, 0x47,
			0x0c, 0xcb, 0x51, 0xa8, 0xe9, 0x8f, 0x91, 0x0f,
			0xa0, 0xba, 0x77, 0x31, 0xce, 0xb2, 0x0c, 0xe0,
			0x70, 0xd5, 0x51, 0xea, 0xc0, 0x6d, 0x7f, 0x96,
		}
		if sha256.Sum256(compact26A428SafeExtractedCompressed) != expected {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile digest mismatch")
			return
		}
		stream, err := gzip.NewReader(bytes.NewReader(compact26A428SafeExtractedCompressed))
		if err != nil {
			compact26A428SafeExtractedErr = err
			return
		}
		encoded, readErr := io.ReadAll(io.LimitReader(stream, 32*1024*1024+1))
		closeErr := stream.Close()
		defer clear(encoded)
		if readErr != nil {
			compact26A428SafeExtractedErr = readErr
			return
		}
		if closeErr != nil {
			compact26A428SafeExtractedErr = closeErr
			return
		}
		if len(encoded) > 32*1024*1024 {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile is too large")
			return
		}
		sections, err := unmarshalCompactProfile(encoded)
		if err != nil {
			compact26A428SafeExtractedErr = err
			return
		}
		if len(sections) != 1 || len(sections[11]) != 52_496 {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile has invalid geometry")
			return
		}
		compact26A428SafeExtractedBlocks = sections[11]
	})
	return compact26A428SafeExtractedBlocks, compact26A428SafeExtractedErr
}
