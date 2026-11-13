package fairplay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func TestRecoveryProfileDiscoversAuthenticatedCallContinuation(t *testing.T) {
	text := make([]byte, 16)
	for index, word := range []uint32{
		0xd73f0911, // blraa x8, x17
		0x14000002, // b +8
		0xd503201f, // nop
		0xd65f03c0, // ret
	} {
		binary.LittleEndian.PutUint32(text[index*4:], word)
	}
	entries, blocks := recoveryProfileStarts(text, 0x1000, []fairPlayFunctionRange{{start: 0x1000, end: 0x1010}})
	if len(entries) != 1 || entries[0] != 0x1000 {
		t.Fatalf("entry points: %#v", entries)
	}
	want := []uint64{0x1000, 0x1004, 0x100c}
	if len(blocks) != len(want) {
		t.Fatalf("block starts: %#v", blocks)
	}
	for index := range want {
		if blocks[index] != want[index] {
			t.Fatalf("block starts: %#v", blocks)
		}
	}
}

func TestRecoveryCodeProfileRoundTrip(t *testing.T) {
	binaryHash := sha256.Sum256([]byte("binary"))
	want := fairPlayRecoveryCodeProfile{
		binaryHash: binaryHash, textAddress: 0x1000, textBytes: 0x1000,
		entryPoints: []uint64{0x1000, 0x1100}, basicBlocks: []uint64{0x1000, 0x1004, 0x1100},
		importStubs: []FairPlayRecoveryImportStub{{Address: 0x1800, Pointer: 0x3000, Name: "_malloc"}},
	}
	encoded, err := marshalFairPlayRecoveryCodeProfile(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalFairPlayRecoveryCodeProfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.binaryHash != want.binaryHash || got.textAddress != want.textAddress || got.textBytes != want.textBytes ||
		!bytes.Equal(uint64Bytes(got.entryPoints), uint64Bytes(want.entryPoints)) || !bytes.Equal(uint64Bytes(got.basicBlocks), uint64Bytes(want.basicBlocks)) || len(got.importStubs) != 1 || got.importStubs[0] != want.importStubs[0] {
		t.Fatalf("profile changed after round trip: %#v", got)
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := unmarshalFairPlayRecoveryCodeProfile(encoded); err == nil {
		t.Fatal("corrupt recovery code profile was accepted")
	}
}

func uint64Bytes(values []uint64) []byte {
	result := make([]byte, len(values)*8)
	for index, value := range values {
		binary.LittleEndian.PutUint64(result[index*8:], value)
	}
	return result
}

func TestExternalRecoveryCodeProfile(t *testing.T) {
	path := os.Getenv("UNFAIRPLAY_PROFILE_BINARY")
	if path == "" {
		t.Skip("external FairPlay profile fixture is not configured")
	}
	first, summary, err := BuildFairPlayRecoveryCodeProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	second, secondSummary, err := BuildFairPlayRecoveryCodeProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || summary != secondSummary || summary.EntryPointCount == 0 || summary.BasicBlockCount < summary.EntryPointCount || summary.ImportStubCount == 0 {
		t.Fatalf("non-deterministic or empty profile: %+v %+v", summary, secondSummary)
	}
	parsed, err := parseCompressedFairPlayRecoveryCodeProfile(first)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(parsed.binaryHash[:]) != summary.BinarySHA256 || len(parsed.entryPoints) != summary.EntryPointCount || len(parsed.basicBlocks) != summary.BasicBlockCount || len(parsed.importStubs) != summary.ImportStubCount {
		t.Fatalf("parsed profile does not match summary: %+v", summary)
	}
	if summary.BinarySHA256 == FairPlayBuild26A428Hash {
		if summary.EntryPointCount != 49329 || summary.BasicBlockCount != 58947 || summary.ImportStubCount != 68 {
			t.Fatalf("unexpected 26A428 profile geometry: %+v", summary)
		}
		foundEntry, foundContinuation := false, false
		for _, address := range parsed.entryPoints {
			foundEntry = foundEntry || address == 0x1001511f0
		}
		for _, address := range parsed.basicBlocks {
			foundContinuation = foundContinuation || address == 0x100151304
		}
		if !foundEntry || !foundContinuation {
			t.Fatal("profile omitted issue-2 handler or BLRAA continuation")
		}
	}
	if summary.BinarySHA256 == FairPlayBuild26B118Hash && (summary.EntryPointCount != 48029 || summary.BasicBlockCount != 57754 || summary.ImportStubCount != 68) {
		t.Fatalf("unexpected 26B118 profile geometry: %+v", summary)
	}
}
