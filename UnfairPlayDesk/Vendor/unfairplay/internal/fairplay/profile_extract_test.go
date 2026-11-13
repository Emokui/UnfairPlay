package fairplay

import (
	"debug/macho"
	"encoding/hex"
	"os"
	"strconv"
	"testing"

	blacktopmacho "github.com/blacktop/go-macho"
)

func TestNormalizedARM64AnchorIgnoresImmediateChanges(t *testing.T) {
	data, err := hex.DecodeString(fairPlayAnchorDefinitions[0].encoded)
	if err != nil {
		t.Fatal(err)
	}
	patterns, err := fairPlayAnchorPatterns()
	if err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), data...)
	mutated[1] ^= 0x20  // MOVK immediate, without changing its operation.
	mutated[16] ^= 0x04 // Branch displacement, without changing B.
	operations, _, valid := normalizedARM64Operations(mutated)
	matches := normalizedOperationMatches(operations, valid, patterns[0].operations, 0x1000, 4)
	if len(matches) != 1 || matches[0] != 0x1000 {
		t.Fatalf("normalized matches = %#v", matches)
	}
}

func TestByteMatchesAreBoundedAndAddressed(t *testing.T) {
	pattern := []byte{1, 2, 3, 4}
	blob := append(append(append([]byte{}, pattern...), pattern...), pattern...)
	matches := allByteMatches(blob, pattern, 0x2000, 2)
	if len(matches) != 2 || matches[0] != 0x2000 || matches[1] != 0x2004 {
		t.Fatalf("byte matches = %#v", matches)
	}
}

func TestExternalFairPlayShapeCandidate(t *testing.T) {
	path, addressText := os.Getenv("UNFAIRPLAY_PROFILE_BINARY"), os.Getenv("UNFAIRPLAY_PROFILE_ADDRESS")
	if path == "" && addressText == "" {
		t.Skip("external FairPlay profile fixture is not configured")
	}
	address, err := strconv.ParseUint(addressText, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	file, err := macho.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	section := file.Section("__text")
	text, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	ranges, err := fairPlayFunctionRanges(path, text, section.Addr)
	if err != nil {
		t.Fatal(err)
	}
	var selected *fairPlayFunctionRange
	for index := range ranges {
		if ranges[index].start == address {
			selected = &ranges[index]
			break
		}
	}
	if selected == nil {
		blacktop, openErr := blacktopmacho.Open(path)
		if openErr == nil {
			defer blacktop.Close()
			if fixups, fixupErr := blacktop.DyldChainedFixups(); fixupErr == nil {
				if parsed, parseErr := fixups.Parse(); parseErr == nil {
					for _, starts := range parsed.Starts {
						for _, rebase := range starts.Rebases() {
							if blacktop.GetBaseAddress()+rebase.Target() == address {
								t.Logf("candidate exists in chained fixups at file offset %#x", rebase.Offset())
							}
						}
					}
				}
			}
		}
		t.Fatalf("candidate root %#x is absent from %d extracted ranges", address, len(ranges))
	}
	encoded := fairPlayShapeDefinitions["private-transform"]
	shapeBytes, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	operations, tokens, err := decodeARM64Shape(shapeBytes)
	if err != nil {
		t.Fatal(err)
	}
	matches := normalizedFunctionShapeMatches(text, operations, tokens, section.Addr,
		[]fairPlayFunctionRange{*selected}, 1)
	if len(matches) != 1 {
		t.Fatalf("candidate %#x did not meet the shape threshold", address)
	}
	t.Logf("candidate %#x score %.6f instructions %d", address, matches[0].Score, matches[0].Instructions)
}
