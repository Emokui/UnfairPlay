package fairplay

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	blacktopmacho "github.com/blacktop/go-macho"
	"golang.org/x/arch/arm64/arm64asm"
)

const FairPlayRecoveryCodeProfileSchema = "unfairplay-recovery-code-profile-v1"

const (
	fairPlayRecoveryCodeProfileMagic   = "FPRCP1\x00\x00"
	fairPlayRecoveryCodeProfileVersion = uint32(1)
	maximumRecoveryProfileBytes        = 16 * 1024 * 1024
	maximumRecoveryProfileAddresses    = 500_000
	maximumRecoveryProfileImports      = 4096
)

type FairPlayRecoveryCodeProfileSummary struct {
	Schema          string `json:"schema"`
	SHA256          string `json:"sha256"`
	Bytes           int    `json:"bytes"`
	BinarySHA256    string `json:"binary_sha256"`
	TextAddress     uint64 `json:"text_address"`
	TextBytes       uint64 `json:"text_bytes"`
	EntryPointCount int    `json:"entry_point_count"`
	BasicBlockCount int    `json:"basic_block_count"`
	ImportStubCount int    `json:"import_stub_count"`
}

type FairPlayRecoveryImportStub struct {
	Address uint64
	Pointer uint64
	Name    string
}

type FairPlayRecoveryCodeLayout struct {
	BinarySHA256 string
	TextAddress  uint64
	TextBytes    uint64
	EntryPoints  []uint64
	BasicBlocks  []uint64
	ImportStubs  []FairPlayRecoveryImportStub
}

type fairPlayRecoveryCodeProfile struct {
	binaryHash  [32]byte
	textAddress uint64
	textBytes   uint64
	entryPoints []uint64
	basicBlocks []uint64
	importStubs []FairPlayRecoveryImportStub
}

func openFairPlayARM64eText(path string) ([]byte, uint64, uint64, string, int64, error) {
	var file *macho.File
	fat, fatErr := macho.OpenFat(path)
	if fatErr == nil {
		defer fat.Close()
		for index := range fat.Arches {
			candidate := fat.Arches[index].File
			if candidate.Cpu == macho.CpuArm64 && uint32(candidate.SubCpu)&0x00ffffff == 2 {
				file = candidate
				if uint32(candidate.SubCpu)&0xff000000 == 0 {
					break
				}
			}
		}
	} else {
		thin, err := macho.Open(path)
		if err != nil {
			return nil, 0, 0, "", 0, fmt.Errorf("open FairPlay Mach-O: %w", err)
		}
		defer thin.Close()
		file = thin
	}
	if file == nil || file.Cpu != macho.CpuArm64 || uint32(file.SubCpu)&0x00ffffff != 2 {
		return nil, 0, 0, "", 0, fmt.Errorf("FairPlay binary is not arm64e")
	}
	section := file.Section("__text")
	if section == nil || section.Seg != "__TEXT" || section.Size == 0 || section.Size%4 != 0 {
		return nil, 0, 0, "", 0, fmt.Errorf("FairPlay binary has no aligned __TEXT,__text section")
	}
	text, err := section.Data()
	if err != nil {
		return nil, 0, 0, "", 0, err
	}
	if uint64(len(text)) != section.Size {
		return nil, 0, 0, "", 0, fmt.Errorf("FairPlay __text bytes are truncated")
	}
	hash, size, err := arm64eMachOHash(path)
	if err != nil {
		return nil, 0, 0, "", 0, err
	}
	return text, section.Addr, section.Size, hash, size, nil
}

func signExtend(value uint64, bits uint) int64 {
	shift := 64 - bits
	return int64(value<<shift) >> shift
}

func fairPlayADRPAddress(word uint32, pc uint64) (uint64, bool) {
	if word&0x9f000000 != 0x90000000 {
		return 0, false
	}
	imm := uint64((word>>5)&0x7ffff)<<2 | uint64(word>>29)&3
	address := int64(pc&^0xfff) + (signExtend(imm, 21) << 12)
	if address < 0 {
		return 0, false
	}
	return uint64(address), true
}

func fairPlayADDImmediate(word uint32) (uint64, bool) {
	if word&0xff000000 != 0x91000000 {
		return 0, false
	}
	value := uint64((word >> 10) & 0xfff)
	if word&(1<<22) != 0 {
		value <<= 12
	}
	return value, true
}

func fairPlayImportStubs(path string) ([]FairPlayRecoveryImportStub, error) {
	var file *blacktopmacho.File
	fat, fatErr := blacktopmacho.OpenFat(path)
	if fatErr == nil {
		defer fat.Close()
		for index := range fat.Arches {
			candidate := fat.Arches[index]
			if uint32(candidate.CPU) == uint32(macho.CpuArm64) && uint32(candidate.SubCPU)&0x00ffffff == 2 {
				file = candidate.File
				if uint32(candidate.SubCPU)&0xff000000 == 0 {
					break
				}
			}
		}
	} else {
		thin, err := blacktopmacho.Open(path)
		if err != nil {
			return nil, err
		}
		defer thin.Close()
		file = thin
	}
	if file == nil {
		return nil, fmt.Errorf("FairPlay binary has no arm64e import image")
	}
	section := file.Section("__TEXT", "__auth_stubs")
	if section == nil {
		return nil, fmt.Errorf("FairPlay binary has no authenticated import stubs")
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data)%16 != 0 {
		return nil, fmt.Errorf("FairPlay authenticated import stubs have invalid geometry")
	}
	bindNames := make(map[uint64]string)
	if binds, bindErr := file.GetBindInfo(); bindErr == nil {
		for _, bind := range binds {
			bindNames[bind.Start+bind.SegOffset] = bind.Name
		}
	}
	if chained, chainedErr := file.DyldChainedFixups(); chainedErr == nil {
		if parsed, parseErr := chained.Parse(); parseErr == nil {
			for _, starts := range parsed.Starts {
				for _, bind := range starts.Binds() {
					address, addressErr := file.GetVMAddress(bind.Offset())
					if addressErr == nil {
						bindNames[address] = bind.Name()
					}
				}
			}
		}
	}
	if len(bindNames) == 0 {
		return nil, fmt.Errorf("FairPlay binary has no resolvable import binds")
	}
	result := make([]FairPlayRecoveryImportStub, 0, len(data)/16)
	for offset := 0; offset < len(data); offset += 16 {
		address := section.Addr + uint64(offset)
		adrpWord := binary.LittleEndian.Uint32(data[offset:])
		page, ok := fairPlayADRPAddress(adrpWord, address)
		if !ok || adrpWord&31 != 17 {
			return nil, fmt.Errorf("authenticated import stub %#x has invalid ADRP", address)
		}
		addWord := binary.LittleEndian.Uint32(data[offset+4:])
		addend, ok := fairPlayADDImmediate(addWord)
		if !ok || addWord&31 != 17 || (addWord>>5)&31 != 17 {
			return nil, fmt.Errorf("authenticated import stub %#x has invalid ADD", address)
		}
		if binary.LittleEndian.Uint32(data[offset+8:]) != 0xf9400230 {
			return nil, fmt.Errorf("authenticated import stub %#x has invalid LDR", address)
		}
		branchWord := binary.LittleEndian.Uint32(data[offset+12:])
		if branchWord&0xfffffc00 != 0xd71f0800 || (branchWord>>5)&31 != 16 || branchWord&31 != 17 {
			return nil, fmt.Errorf("authenticated import stub %#x has invalid BRAA", address)
		}
		pointer := page + addend
		name := bindNames[pointer]
		if name == "" {
			return nil, fmt.Errorf("authenticated import stub %#x has no bind at %#x", address, pointer)
		}
		result = append(result, FairPlayRecoveryImportStub{Address: address, Pointer: pointer, Name: name})
	}
	return result, nil
}

func fairPlayPCRelativeTarget(instruction arm64asm.Inst, pc uint64) (uint64, bool) {
	for _, argument := range instruction.Args {
		relative, ok := argument.(arm64asm.PCRel)
		if !ok {
			continue
		}
		target := int64(pc) + int64(relative)
		if target < 0 {
			return 0, false
		}
		return uint64(target), true
	}
	return 0, false
}

func fairPlayConditionalBranch(instruction arm64asm.Inst) bool {
	for _, argument := range instruction.Args {
		if _, ok := argument.(arm64asm.Cond); ok {
			return true
		}
	}
	return false
}

func fairPlayAuthenticatedCall(word uint32) bool {
	switch word & 0xfffffc00 {
	case 0xd73f0800, 0xd73f0c00: // BLRAA/BLRAB Xn, Xm
		return true
	}
	switch word & 0xfffffc1f {
	case 0xd63f081f, 0xd63f0c1f: // BLRAAZ/BLRABZ Xn
		return true
	}
	return false
}

func fairPlayAuthenticatedBranch(word uint32) bool {
	switch word & 0xfffffc00 {
	case 0xd71f0800, 0xd71f0c00: // BRAA/BRAB Xn, Xm
		return true
	}
	switch word & 0xfffffc1f {
	case 0xd61f081f, 0xd61f0c1f: // BRAAZ/BRABZ Xn
		return true
	}
	return false
}

func addressInFairPlayText(address, base uint64, text []byte) bool {
	return address >= base && address < base+uint64(len(text)) && (address-base)%4 == 0
}

func recoveryProfileStarts(text []byte, textBase uint64, ranges []fairPlayFunctionRange) ([]uint64, []uint64) {
	entries := make(map[uint64]bool)
	blocks := make(map[uint64]bool)
	var pending []uint64
	addEntry := func(address uint64) {
		if addressInFairPlayText(address, textBase, text) {
			entries[address] = true
		}
	}
	addBlock := func(address uint64) {
		if addressInFairPlayText(address, textBase, text) && !blocks[address] {
			blocks[address] = true
			pending = append(pending, address)
		}
	}
	for _, function := range ranges {
		addEntry(function.start)
		addBlock(function.start)
	}
	scanned := make(map[uint64]bool)
	textEnd := textBase + uint64(len(text))
	for len(pending) != 0 {
		start := pending[0]
		pending = pending[1:]
		if scanned[start] {
			continue
		}
		scanned[start] = true
		limit := min(start+512*4, textEnd)
		for pc := start; pc+4 <= limit; pc += 4 {
			offset := pc - textBase
			word := binary.LittleEndian.Uint32(text[offset : offset+4])
			if fairPlayAuthenticatedCall(word) {
				addBlock(pc + 4)
				break
			}
			if fairPlayAuthenticatedBranch(word) {
				break
			}
			if _, _, recognized, terminal := normalizedUndecodedInstruction(text[offset : offset+4]); recognized && terminal {
				break
			}
			instruction, err := arm64asm.Decode(text[offset : offset+4])
			if err != nil {
				continue
			}
			switch instruction.Op.String() {
			case "BL":
				if target, ok := fairPlayPCRelativeTarget(instruction, pc); ok {
					addEntry(target)
					addBlock(target)
				}
				addBlock(pc + 4)
				break
			case "BLR":
				addBlock(pc + 4)
				break
			case "B":
				if target, ok := fairPlayPCRelativeTarget(instruction, pc); ok {
					addBlock(target)
				}
				if fairPlayConditionalBranch(instruction) {
					addBlock(pc + 4)
				}
				break
			case "CBZ", "CBNZ", "TBZ", "TBNZ":
				if target, ok := fairPlayPCRelativeTarget(instruction, pc); ok {
					addBlock(target)
				}
				addBlock(pc + 4)
				break
			case "BR", "RET":
				break
			default:
				continue
			}
			break
		}
	}
	ordered := func(values map[uint64]bool) []uint64 {
		result := make([]uint64, 0, len(values))
		for address := range values {
			result = append(result, address)
		}
		sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
		return result
	}
	return ordered(entries), ordered(blocks)
}

func marshalFairPlayRecoveryCodeProfile(profile fairPlayRecoveryCodeProfile) ([]byte, error) {
	textEnd := profile.textAddress + profile.textBytes
	if textEnd < profile.textAddress || len(profile.entryPoints) == 0 || len(profile.basicBlocks) == 0 || len(profile.importStubs) == 0 || len(profile.entryPoints) > maximumRecoveryProfileAddresses || len(profile.basicBlocks) > maximumRecoveryProfileAddresses || len(profile.importStubs) > maximumRecoveryProfileImports {
		return nil, fmt.Errorf("FairPlay recovery code profile has invalid geometry")
	}
	var output bytes.Buffer
	output.WriteString(fairPlayRecoveryCodeProfileMagic)
	_ = binary.Write(&output, binary.LittleEndian, fairPlayRecoveryCodeProfileVersion)
	_ = binary.Write(&output, binary.LittleEndian, uint32(0))
	output.Write(profile.binaryHash[:])
	_ = binary.Write(&output, binary.LittleEndian, profile.textAddress)
	_ = binary.Write(&output, binary.LittleEndian, profile.textBytes)
	_ = binary.Write(&output, binary.LittleEndian, uint32(len(profile.entryPoints)))
	_ = binary.Write(&output, binary.LittleEndian, uint32(len(profile.basicBlocks)))
	_ = binary.Write(&output, binary.LittleEndian, uint32(len(profile.importStubs)))
	_ = binary.Write(&output, binary.LittleEndian, uint32(0))
	for _, addresses := range [][]uint64{profile.entryPoints, profile.basicBlocks} {
		previous := uint64(0)
		for index, address := range addresses {
			if address < profile.textAddress || address >= textEnd || index != 0 && address <= previous {
				return nil, fmt.Errorf("FairPlay recovery code profile has invalid address %#x", address)
			}
			_ = binary.Write(&output, binary.LittleEndian, address)
			previous = address
		}
	}
	previousStub := uint64(0)
	for index, stub := range profile.importStubs {
		if stub.Address == 0 || index != 0 && stub.Address <= previousStub || stub.Pointer == 0 || stub.Name == "" || len(stub.Name) > int(^uint16(0)) || !utf8.ValidString(stub.Name) || strings.IndexByte(stub.Name, 0) >= 0 {
			return nil, fmt.Errorf("FairPlay recovery code profile has invalid import stub")
		}
		_ = binary.Write(&output, binary.LittleEndian, stub.Address)
		_ = binary.Write(&output, binary.LittleEndian, stub.Pointer)
		_ = binary.Write(&output, binary.LittleEndian, uint16(len(stub.Name)))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		output.WriteString(stub.Name)
		previousStub = stub.Address
	}
	payload := output.Bytes()
	digest := sha256.Sum256(payload)
	return append(payload, digest[:]...), nil
}

func unmarshalFairPlayRecoveryCodeProfile(encoded []byte) (fairPlayRecoveryCodeProfile, error) {
	var result fairPlayRecoveryCodeProfile
	if len(encoded) < 112 {
		return result, fmt.Errorf("FairPlay recovery code profile is truncated")
	}
	payload, checksum := encoded[:len(encoded)-32], encoded[len(encoded)-32:]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(checksum, digest[:]) {
		return result, fmt.Errorf("FairPlay recovery code profile checksum mismatch")
	}
	reader := bytes.NewReader(payload)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || string(magic[:]) != fairPlayRecoveryCodeProfileMagic {
		return result, fmt.Errorf("invalid FairPlay recovery code profile magic")
	}
	var version, reserved uint32
	if binary.Read(reader, binary.LittleEndian, &version) != nil || version != fairPlayRecoveryCodeProfileVersion || binary.Read(reader, binary.LittleEndian, &reserved) != nil || reserved != 0 {
		return result, fmt.Errorf("unsupported FairPlay recovery code profile version")
	}
	if _, err := io.ReadFull(reader, result.binaryHash[:]); err != nil {
		return result, err
	}
	if binary.Read(reader, binary.LittleEndian, &result.textAddress) != nil || binary.Read(reader, binary.LittleEndian, &result.textBytes) != nil || result.textBytes == 0 || result.textAddress+result.textBytes < result.textAddress {
		return result, fmt.Errorf("invalid FairPlay recovery code profile text geometry")
	}
	var entryCount, blockCount, stubCount uint32
	if binary.Read(reader, binary.LittleEndian, &entryCount) != nil || binary.Read(reader, binary.LittleEndian, &blockCount) != nil || binary.Read(reader, binary.LittleEndian, &stubCount) != nil || binary.Read(reader, binary.LittleEndian, &reserved) != nil || reserved != 0 || entryCount == 0 || blockCount == 0 || stubCount == 0 || entryCount > maximumRecoveryProfileAddresses || blockCount > maximumRecoveryProfileAddresses || stubCount > maximumRecoveryProfileImports {
		return result, fmt.Errorf("invalid FairPlay recovery code profile counts")
	}
	readAddresses := func(count uint32) ([]uint64, error) {
		addresses := make([]uint64, count)
		for index := range addresses {
			if err := binary.Read(reader, binary.LittleEndian, &addresses[index]); err != nil {
				return nil, err
			}
			if addresses[index] < result.textAddress || addresses[index] >= result.textAddress+result.textBytes || index != 0 && addresses[index] <= addresses[index-1] {
				return nil, fmt.Errorf("invalid FairPlay recovery code profile address")
			}
		}
		return addresses, nil
	}
	var err error
	result.entryPoints, err = readAddresses(entryCount)
	if err != nil {
		return result, err
	}
	result.basicBlocks, err = readAddresses(blockCount)
	if err != nil {
		return result, err
	}
	result.importStubs = make([]FairPlayRecoveryImportStub, stubCount)
	previousStub := uint64(0)
	for index := range result.importStubs {
		stub := &result.importStubs[index]
		var nameBytes, stubReserved uint16
		if binary.Read(reader, binary.LittleEndian, &stub.Address) != nil || binary.Read(reader, binary.LittleEndian, &stub.Pointer) != nil || binary.Read(reader, binary.LittleEndian, &nameBytes) != nil || binary.Read(reader, binary.LittleEndian, &stubReserved) != nil || stubReserved != 0 || nameBytes == 0 || stub.Address == 0 || index != 0 && stub.Address <= previousStub || stub.Pointer == 0 {
			return result, fmt.Errorf("invalid FairPlay recovery code profile import stub")
		}
		name := make([]byte, nameBytes)
		if _, err := io.ReadFull(reader, name); err != nil {
			return result, err
		}
		stub.Name = string(name)
		if !utf8.ValidString(stub.Name) || strings.IndexByte(stub.Name, 0) >= 0 {
			return result, fmt.Errorf("invalid FairPlay recovery code profile import name")
		}
		previousStub = stub.Address
	}
	if reader.Len() != 0 {
		return result, fmt.Errorf("FairPlay recovery code profile has trailing data")
	}
	return result, nil
}

func BuildFairPlayRecoveryCodeProfile(path string) ([]byte, FairPlayRecoveryCodeProfileSummary, error) {
	var summary FairPlayRecoveryCodeProfileSummary
	layout, err := InspectFairPlayRecoveryCodeLayout(path)
	if err != nil {
		return nil, summary, err
	}
	hashBytes, err := hex.DecodeString(layout.BinarySHA256)
	if err != nil || len(hashBytes) != sha256.Size {
		return nil, summary, fmt.Errorf("invalid FairPlay binary SHA256")
	}
	var binaryHash [32]byte
	copy(binaryHash[:], hashBytes)
	encoded, err := marshalFairPlayRecoveryCodeProfile(fairPlayRecoveryCodeProfile{
		binaryHash: binaryHash, textAddress: layout.TextAddress, textBytes: layout.TextBytes,
		entryPoints: layout.EntryPoints, basicBlocks: layout.BasicBlocks, importStubs: layout.ImportStubs,
	})
	if err != nil {
		return nil, summary, err
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, summary, err
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err := writer.Write(encoded); err != nil {
		return nil, summary, err
	}
	if err := writer.Close(); err != nil {
		return nil, summary, err
	}
	profileBytes := compressed.Bytes()
	profileSHA256 := sha256.Sum256(profileBytes)
	summary = FairPlayRecoveryCodeProfileSummary{
		Schema: FairPlayRecoveryCodeProfileSchema, SHA256: hex.EncodeToString(profileSHA256[:]), Bytes: len(profileBytes),
		BinarySHA256: layout.BinarySHA256, TextAddress: layout.TextAddress, TextBytes: layout.TextBytes,
		EntryPointCount: len(layout.EntryPoints), BasicBlockCount: len(layout.BasicBlocks),
		ImportStubCount: len(layout.ImportStubs),
	}
	return append([]byte(nil), profileBytes...), summary, nil
}

func InspectFairPlayRecoveryCodeLayout(path string) (FairPlayRecoveryCodeLayout, error) {
	var result FairPlayRecoveryCodeLayout
	text, textAddress, textBytes, binarySHA256, _, err := openFairPlayARM64eText(path)
	if err != nil {
		return result, err
	}
	ranges, err := fairPlayFunctionRanges(path, text, textAddress)
	if err != nil {
		return result, err
	}
	entries, blocks := recoveryProfileStarts(text, textAddress, ranges)
	stubs, err := fairPlayImportStubs(path)
	if err != nil {
		return result, err
	}
	result = FairPlayRecoveryCodeLayout{
		BinarySHA256: binarySHA256, TextAddress: textAddress, TextBytes: textBytes,
		EntryPoints: entries, BasicBlocks: blocks, ImportStubs: stubs,
	}
	return result, nil
}

func parseCompressedFairPlayRecoveryCodeProfile(compressed []byte) (fairPlayRecoveryCodeProfile, error) {
	stream, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fairPlayRecoveryCodeProfile{}, err
	}
	encoded, readErr := io.ReadAll(io.LimitReader(stream, maximumRecoveryProfileBytes+1))
	closeErr := stream.Close()
	if readErr != nil {
		return fairPlayRecoveryCodeProfile{}, readErr
	}
	if closeErr != nil {
		return fairPlayRecoveryCodeProfile{}, closeErr
	}
	if len(encoded) > maximumRecoveryProfileBytes {
		return fairPlayRecoveryCodeProfile{}, fmt.Errorf("FairPlay recovery code profile is too large")
	}
	return unmarshalFairPlayRecoveryCodeProfile(encoded)
}
