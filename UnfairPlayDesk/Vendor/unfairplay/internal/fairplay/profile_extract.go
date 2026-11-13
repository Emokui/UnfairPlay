package fairplay

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"sort"
	"strings"

	blacktopmacho "github.com/blacktop/go-macho"
	"golang.org/x/arch/arm64/arm64asm"
)

const FairPlayBinaryProfileSchema = "unfairplay-binary-profile-v1"

type FairPlayBinaryAnchor struct {
	Name              string               `json:"name"`
	ReferenceAddress  uint64               `json:"reference_address"`
	InstructionCount  int                  `json:"instruction_count"`
	PortableBoundary  bool                 `json:"portable_boundary"`
	ExactMatches      []uint64             `json:"exact_matches,omitempty"`
	NormalizedMatches []uint64             `json:"normalized_matches,omitempty"`
	ShapeMatches      []FairPlayShapeMatch `json:"shape_matches,omitempty"`
}

type FairPlayShapeMatch struct {
	Address      uint64  `json:"address"`
	Instructions int     `json:"instructions"`
	Score        float64 `json:"score"`
}

type FairPlayBinaryProfile struct {
	Schema              string                              `json:"schema"`
	SHA256              string                              `json:"sha256"`
	Bytes               int64                               `json:"bytes"`
	TextAddress         uint64                              `json:"text_address"`
	TextBytes           uint64                              `json:"text_bytes"`
	StructuralFamily    string                              `json:"structural_family,omitempty"`
	UniqueAnchorCount   int                                 `json:"unique_anchor_count"`
	ExactAnchorCount    int                                 `json:"exact_anchor_count"`
	PortableAnchorCount int                                 `json:"portable_anchor_count"`
	ShapeAnchorCount    int                                 `json:"shape_anchor_count"`
	PortableCandidate   bool                                `json:"portable_candidate"`
	Anchors             []FairPlayBinaryAnchor              `json:"anchors"`
	RecoveryCodeProfile *FairPlayRecoveryCodeProfileSummary `json:"recovery_code_profile,omitempty"`
}

type fairPlayAnchorPattern struct {
	name       string
	address    uint64
	portable   bool
	bytes      []byte
	operations []arm64asm.Op
}

type normalizedARM64Token uint64

const (
	normalizedOpADRL arm64asm.Op = 0xfffe
	normalizedOpBRAA arm64asm.Op = 0xfffd
	normalizedOpRET  arm64asm.Op = 0xfffc
)

type fairPlayFunctionRange struct {
	start, end uint64
}

var fairPlayAnchorDefinitions = []struct {
	name, encoded string
	address       uint64
	portable      bool
}{
	{"account-entry", "4857bb720805000a0900130b2801084b21000014c7ed15350c7d1f53eb03282a6b7d1f538d150c4b0e0380526b350e1b6b010a0b4a010c0beada6af80c269252", 0x100cd1c18, true},
	{"state-bootstrap", "cb010a0a91020d0b82d871b8420018ca42805c8ba3d871b8630018ca7c08ac9b620117cac227c29a420006cad1da71b8310218ca310ab39b31423c8be204118a", 0x10057ae74, true},
	{"record-selection", "f407409194c20e9148c68c526821ae727a02080b48698f526821ae726802080be9fb46f929d968f888a496d2883ea0f2e873d4f2c8a7e6f2f95b46f9fb5f46f9", 0x1006b10a0, true},
	{"sinf-entry", "899a9152494bbb72aa9982520b01090beb0703b968010a4aa80314b8883d001249f69a524992b2726901094a2a7d081b481d0012493d0853815345b9ae424bb9", 0x10008a644, true},
	{"sinf-consumer", "886b683889258552a935a5724b01090b49038052eb0704b96901094aaa1880520a010acaf5cf41f9aa6a6a382901084a0b09805208010b4a8b791e12c7239252", 0x100234cdc, true},
	{"private-transform", "49048052094ca0728901092a6b0500f1ea6a6b38117900d0318a45b934434bb93502144ab5020f4ab57e101ba18353f83600358bd6024039d602004ad6497638", 0x10015320c, false},
	{"frame-builder", "49c39b52a80359380a0d40d2cb148052e87d00d00f8945b9a80356f8010140b928000f4be1e703b908010b4ac3148052eb999a528b4ba1720b7d0b1bebcf01f9", 0x1000b7ac4, false},
	{"aes-frame-core", "eac704b9fff303b9289097124801084a8801080afb239252fb94ab7208011bcae84f02f9886b683889258552a935a5724b01090b49038052eb0704b96901094a", 0x100234cb8, false},
}

var fairPlayShapeDefinitions = map[string]string{
	"private-transform": "49048052094ca0728901092a6b0500f1ea6a6b38117900d0318a45b934434bb93502144ab5020f4ab57e101ba18353f83600358bd6024039d602004ad6497638b502164a9102114b31020f4a317e101b341e4092b51e00125603148bd6024039d602034a964b7638b5de15113602164ad61e0012d6be3511a18350f83400148b4178009021c01b91365876f8940240399402064afe0317aaf76742f9f44a7438355875f8770d40923102144a311e0012311a2511f402048bd402148b315871f8f602078b3102168bf602028bb502168b36790051ca020a4af67e051bf7031eaabe0350f84a01164ab50240394a01154a94024039310240399102114a4a01114a0a692b38ea179f1a4a7d131b4a010d4a6adb6af8110883d251091fd7",
}

func fairPlayAnchorPatterns() ([]fairPlayAnchorPattern, error) {
	result := make([]fairPlayAnchorPattern, 0, len(fairPlayAnchorDefinitions))
	for _, definition := range fairPlayAnchorDefinitions {
		data, err := hex.DecodeString(definition.encoded)
		if err != nil || len(data)%4 != 0 {
			return nil, fmt.Errorf("invalid FairPlay anchor %q", definition.name)
		}
		operations := make([]arm64asm.Op, len(data)/4)
		for index := range operations {
			instruction, decodeErr := arm64asm.Decode(data[index*4 : index*4+4])
			if decodeErr != nil {
				return nil, fmt.Errorf("decode FairPlay anchor %q: %w", definition.name, decodeErr)
			}
			operations[index] = instruction.Op
		}
		result = append(result, fairPlayAnchorPattern{
			name: definition.name, address: definition.address, portable: definition.portable,
			bytes: data, operations: operations,
		})
	}
	return result, nil
}

func allByteMatches(blob, pattern []byte, base uint64, limit int) []uint64 {
	var result []uint64
	for cursor := 0; cursor <= len(blob)-len(pattern); {
		index := bytes.Index(blob[cursor:], pattern)
		if index < 0 {
			break
		}
		offset := cursor + index
		if offset%4 != 0 {
			cursor = offset + 1
			continue
		}
		result = append(result, base+uint64(offset))
		if len(result) == limit {
			break
		}
		cursor = offset + 4
	}
	return result
}

func arm64OperandKind(argument arm64asm.Arg) uint8 {
	if argument == nil {
		return 0
	}
	switch argument.(type) {
	case arm64asm.Reg, arm64asm.RegSP,
		arm64asm.RegisterWithArrangement, arm64asm.RegisterWithArrangementAndIndex:
		return 1
	case arm64asm.MemExtend:
		return 3
	case arm64asm.MemImmediate:
		return 4
	case arm64asm.RegExtshiftAmount:
		return 8
	case arm64asm.PCRel:
		return 7
	case arm64asm.Cond:
		return 14
	case arm64asm.Systemreg, arm64asm.Pstatefield:
		return 2
	}
	name := fmt.Sprintf("%T", argument)
	if strings.Contains(name, "Imm") {
		return 5
	}
	return 7
}

func arm64InstructionToken(instruction arm64asm.Inst) normalizedARM64Token {
	result := normalizedARM64Token(instruction.Op) << 40
	for index, argument := range instruction.Args {
		result |= normalizedARM64Token(arm64OperandKind(argument)) << (index * 8)
	}
	return result
}

func normalizedToken(operation arm64asm.Op, kinds ...uint8) normalizedARM64Token {
	result := normalizedARM64Token(operation) << 40
	for index, kind := range kinds {
		result |= normalizedARM64Token(kind) << (index * 8)
	}
	return result
}

func sameRegister(left, right arm64asm.Arg) bool {
	return left != nil && right != nil && fmt.Sprint(left) == fmt.Sprint(right)
}

func normalizedUndecodedInstruction(data []byte) (arm64asm.Op, normalizedARM64Token, bool, bool) {
	if len(data) < 4 {
		return 0, 0, false, false
	}
	word := binary.LittleEndian.Uint32(data)
	switch {
	case word&0xfffffc00 == 0xd71f0800 || word&0xfffffc00 == 0xd71f0c00:
		return normalizedOpBRAA, normalizedToken(normalizedOpBRAA, 1, 1), true, true
	case word == 0xd65f0bff || word == 0xd65f0fff:
		return normalizedOpRET, normalizedToken(normalizedOpRET, 1), true, true
	default:
		return 0, 0, false, false
	}
}

func normalizedARM64Operations(text []byte) ([]arm64asm.Op, []normalizedARM64Token, []bool) {
	operations := make([]arm64asm.Op, len(text)/4)
	tokens := make([]normalizedARM64Token, len(operations))
	valid := make([]bool, len(operations))
	for index := range operations {
		instruction, err := arm64asm.Decode(text[index*4 : index*4+4])
		if err == nil {
			operations[index], valid[index] = instruction.Op, true
			tokens[index] = arm64InstructionToken(instruction)
		} else if operation, token, recognized, _ := normalizedUndecodedInstruction(text[index*4 : index*4+4]); recognized {
			operations[index], tokens[index], valid[index] = operation, token, true
		}
	}
	return operations, tokens, valid
}

func normalizedOperationMatches(operations []arm64asm.Op, valid []bool, pattern []arm64asm.Op, base uint64, limit int) []uint64 {
	var result []uint64
	for start := 0; start+len(pattern) <= len(operations); start++ {
		if !valid[start] || operations[start] != pattern[0] {
			continue
		}
		matched := true
		for index := 1; index < len(pattern); index++ {
			if !valid[start+index] || operations[start+index] != pattern[index] {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, base+uint64(start*4))
			if len(result) == limit {
				break
			}
		}
	}
	return result
}

func decodeARM64Shape(data []byte) ([]arm64asm.Op, []normalizedARM64Token, error) {
	if len(data)%4 != 0 {
		return nil, nil, fmt.Errorf("ARM64 shape has invalid size")
	}
	operations := make([]arm64asm.Op, 0, len(data)/4)
	tokens := make([]normalizedARM64Token, 0, len(data)/4)
	for index := 0; index < len(data)/4; index++ {
		instruction, err := arm64asm.Decode(data[index*4 : index*4+4])
		if err != nil {
			if operation, token, recognized, _ := normalizedUndecodedInstruction(data[index*4 : index*4+4]); recognized {
				operations = append(operations, operation)
				tokens = append(tokens, token)
			}
			continue
		}
		var next arm64asm.Inst
		nextValid := false
		if index+1 < len(data)/4 {
			next, err = arm64asm.Decode(data[(index+1)*4 : (index+2)*4])
			nextValid = err == nil
		}
		if instruction.Op == arm64asm.MOV && nextValid && next.Op == arm64asm.MOVK &&
			sameRegister(instruction.Args[0], next.Args[0]) {
			operations = append(operations, arm64asm.MOV)
			tokens = append(tokens, arm64InstructionToken(instruction))
			index++
			continue
		}
		if instruction.Op == arm64asm.ADRP && nextValid && next.Op == arm64asm.ADD &&
			sameRegister(instruction.Args[0], next.Args[0]) &&
			sameRegister(instruction.Args[0], next.Args[1]) {
			operations = append(operations, normalizedOpADRL)
			tokens = append(tokens, normalizedToken(normalizedOpADRL, 1, 5))
			index++
			continue
		}
		if instruction.Op == arm64asm.MOVK {
			instruction.Op = arm64asm.MOV
		}
		operations = append(operations, instruction.Op)
		tokens = append(tokens, arm64InstructionToken(instruction))
	}
	if len(tokens) < 3 {
		return nil, nil, fmt.Errorf("ARM64 shape has too few decodable instructions")
	}
	return operations, tokens, nil
}

func fairPlayHandlerEnd(text []byte, base, start uint64) (uint64, bool) {
	if start < base || start-base >= uint64(len(text)) || (start-base)%4 != 0 {
		return 0, false
	}
	offset := int(start - base)
	for instructions := 0; instructions < 512 && offset+4 <= len(text); instructions++ {
		data := text[offset : offset+4]
		_, _, _, rawTerminator := normalizedUndecodedInstruction(data)
		instruction, err := arm64asm.Decode(data)
		offset += 4
		if rawTerminator {
			return base + uint64(offset), true
		}
		if err != nil {
			continue
		}
		switch instruction.Op.String() {
		case "BRAA", "BRAB", "BR", "RET", "RETAB":
			return base + uint64(offset), true
		}
	}
	return 0, false
}

func fairPlayFunctionRanges(path string, text []byte, textBase uint64) ([]fairPlayFunctionRange, error) {
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
		return nil, fmt.Errorf("FairPlay binary has no arm64e function table")
	}
	functions := file.GetFunctions()
	result := make([]fairPlayFunctionRange, 0, len(functions))
	seen := make(map[uint64]bool)
	for _, function := range functions {
		if function.EndAddr > function.StartAddr {
			result = append(result, fairPlayFunctionRange{start: function.StartAddr, end: function.EndAddr})
			seen[function.StartAddr] = true
		}
	}
	if fixups, err := file.DyldChainedFixups(); err == nil {
		fixups, err = fixups.Parse()
		if err != nil {
			return result, err
		}
		base := file.GetBaseAddress()
		for _, starts := range fixups.Starts {
			for _, rebase := range starts.Rebases() {
				start := base + rebase.Target()
				if seen[start] {
					continue
				}
				if end, ok := fairPlayHandlerEnd(text, textBase, start); ok {
					result = append(result, fairPlayFunctionRange{start: start, end: end})
					seen[start] = true
				}
			}
		}
	}
	if rebases, err := file.GetRebaseInfo(); err == nil {
		base := file.GetBaseAddress()
		for _, rebase := range rebases {
			candidates := [...]uint64{
				rebase.Value,
				base + (rebase.Value & 0xffffffff),
				base + (rebase.Value & 0x0000ffffffffffff),
			}
			for _, start := range candidates {
				if seen[start] {
					continue
				}
				if end, ok := fairPlayHandlerEnd(text, textBase, start); ok {
					result = append(result, fairPlayFunctionRange{start: start, end: end})
					seen[start] = true
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("FairPlay binary has no function starts")
	}
	return result, nil
}

func histogramCosine[T comparable](left, right []T) float64 {
	leftCounts, rightCounts := make(map[T]int), make(map[T]int)
	for _, value := range left {
		leftCounts[value]++
	}
	for _, value := range right {
		rightCounts[value]++
	}
	dot, leftNorm, rightNorm := 0, 0, 0
	for value, count := range leftCounts {
		dot += count * rightCounts[value]
		leftNorm += count * count
	}
	for _, count := range rightCounts {
		rightNorm += count * count
	}
	if leftNorm == 0 || rightNorm == 0 {
		return 0
	}
	return float64(dot) / math.Sqrt(float64(leftNorm*rightNorm))
}

func tokenGramOverlap(left, right []normalizedARM64Token) float64 {
	if len(left) < 3 {
		return 0
	}
	leftCounts, rightCounts := make(map[uint64]int), make(map[uint64]int)
	for index := 0; index+2 < len(left); index++ {
		leftCounts[operationGram(left[index], left[index+1], left[index+2])]++
	}
	for index := 0; index+2 < len(right); index++ {
		rightCounts[operationGram(right[index], right[index+1], right[index+2])]++
	}
	shared := 0
	for gram, count := range leftCounts {
		shared += min(count, rightCounts[gram])
	}
	return float64(shared) / float64(len(left)-2)
}

func normalizedFunctionShapeMatches(text []byte, referenceOperations []arm64asm.Op, referenceTokens []normalizedARM64Token, base uint64,
	functions []fairPlayFunctionRange, limit int) []FairPlayShapeMatch {
	var matches []FairPlayShapeMatch
	for _, function := range functions {
		if function.start < base || function.end <= function.start || function.end > base+uint64(len(text)) {
			continue
		}
		start := int(function.start - base)
		end := int(function.end - base)
		candidateOperations, candidateTokens, err := decodeARM64Shape(text[start:end])
		if err != nil {
			continue
		}
		if len(candidateTokens) < len(referenceTokens)*35/100 || len(candidateTokens) > len(referenceTokens)*285/100 {
			continue
		}
		mnemonicScore := histogramCosine(referenceOperations, candidateOperations)
		tokenScore := histogramCosine(referenceTokens, candidateTokens)
		gramScore := tokenGramOverlap(referenceTokens, candidateTokens)
		sizeScore := float64(min(len(referenceTokens), len(candidateTokens))) / float64(max(len(referenceTokens), len(candidateTokens)))
		score := mnemonicScore*0.25 + tokenScore*0.30 + gramScore*0.30 + sizeScore*0.15
		if score >= 0.35 {
			matches = append(matches, FairPlayShapeMatch{Address: function.start, Instructions: len(candidateTokens), Score: score})
		}
	}
	sort.Slice(matches, func(left, right int) bool {
		if matches[left].Score != matches[right].Score {
			return matches[left].Score > matches[right].Score
		}
		return matches[left].Address < matches[right].Address
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

func operationGram(left, middle, right normalizedARM64Token) uint64 {
	return bits.RotateLeft64(uint64(left)*0x9e3779b185ebca87, 11) ^
		bits.RotateLeft64(uint64(middle)*0xc2b2ae3d27d4eb4f, 29) ^
		bits.RotateLeft64(uint64(right)*0x165667b19e3779f9, 47)
}

func normalizedShapeMatches(operations []normalizedARM64Token, valid []bool, reference []normalizedARM64Token, base uint64, limit int) []FairPlayShapeMatch {
	if len(reference) < 3 || len(operations) < 3 {
		return nil
	}
	referenceCounts := make(map[uint64]int)
	for index := 0; index+2 < len(reference); index++ {
		referenceCounts[operationGram(reference[index], reference[index+1], reference[index+2])]++
	}
	referenceTotal := len(reference) - 2
	referenceOperations := make(map[normalizedARM64Token]int)
	referenceNormSquared := 0
	for _, operation := range reference {
		referenceOperations[operation]++
	}
	for _, count := range referenceOperations {
		referenceNormSquared += count * count
	}
	targetGrams := make([]uint64, len(operations)-2)
	targetGramValid := make([]bool, len(targetGrams))
	for index := range targetGrams {
		if valid[index] && valid[index+1] && valid[index+2] {
			targetGrams[index] = operationGram(operations[index], operations[index+1], operations[index+2])
			targetGramValid[index] = true
		}
	}
	minimum := max(3, len(reference)*3/4)
	maximum := min(len(operations), len(reference)*3/2)
	step := max(1, len(reference)/16)
	var matches []FairPlayShapeMatch
	for window := minimum; window <= maximum; window += step {
		gramWindow := window - 2
		counts := make(map[uint64]int)
		operationCounts := make(map[normalizedARM64Token]int)
		shared := 0
		operationDot, operationNormSquared := 0, 0
		adjust := func(key uint64, delta int) {
			want := referenceCounts[key]
			if want == 0 {
				return
			}
			before := min(counts[key], want)
			counts[key] += delta
			after := min(counts[key], want)
			shared += after - before
		}
		for index := 0; index < gramWindow; index++ {
			if targetGramValid[index] {
				adjust(targetGrams[index], 1)
			}
		}
		adjustOperation := func(operation normalizedARM64Token, delta int) {
			before := operationCounts[operation]
			operationDot += referenceOperations[operation] * delta
			operationCounts[operation] += delta
			after := operationCounts[operation]
			operationNormSquared += after*after - before*before
		}
		for index := 0; index < window; index++ {
			if valid[index] {
				adjustOperation(operations[index], 1)
			}
		}
		for start := 0; start+window <= len(operations); start++ {
			gramScore := float64(2*shared) / float64(referenceTotal+gramWindow)
			operationScore := 0.0
			if operationNormSquared != 0 {
				operationScore = float64(operationDot) / math.Sqrt(float64(referenceNormSquared*operationNormSquared))
			}
			sizeScore := float64(min(len(reference), window)) / float64(max(len(reference), window))
			score := gramScore*0.45 + operationScore*0.45 + sizeScore*0.10
			if score >= 0.20 {
				matches = append(matches, FairPlayShapeMatch{
					Address: base + uint64(start*4), Instructions: window, Score: score,
				})
				if len(matches) > limit*32 {
					sort.Slice(matches, func(left, right int) bool { return matches[left].Score > matches[right].Score })
					matches = matches[:limit*8]
				}
			}
			if start+window == len(operations) {
				break
			}
			if targetGramValid[start] {
				adjust(targetGrams[start], -1)
			}
			if valid[start] {
				adjustOperation(operations[start], -1)
			}
			incoming := start + gramWindow
			if targetGramValid[incoming] {
				adjust(targetGrams[incoming], 1)
			}
			incomingOperation := start + window
			if valid[incomingOperation] {
				adjustOperation(operations[incomingOperation], 1)
			}
		}
	}
	sort.Slice(matches, func(left, right int) bool {
		if matches[left].Score != matches[right].Score {
			return matches[left].Score > matches[right].Score
		}
		return matches[left].Address < matches[right].Address
	})
	filtered := make([]FairPlayShapeMatch, 0, min(limit, len(matches)))
	for _, candidate := range matches {
		near := false
		for _, previous := range filtered {
			distance := candidate.Address - previous.Address
			if candidate.Address < previous.Address {
				distance = previous.Address - candidate.Address
			}
			if distance < uint64(max(candidate.Instructions, previous.Instructions)*4) {
				near = true
				break
			}
		}
		if !near {
			filtered = append(filtered, candidate)
			if len(filtered) == limit {
				break
			}
		}
	}
	return filtered
}

func InspectFairPlayBinaryProfile(path string) (FairPlayBinaryProfile, error) {
	var result FairPlayBinaryProfile
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
			return result, fmt.Errorf("open FairPlay Mach-O: %w", err)
		}
		defer thin.Close()
		file = thin
	}
	if file == nil || file.Cpu != macho.CpuArm64 || uint32(file.SubCpu)&0x00ffffff != 2 {
		return result, fmt.Errorf("FairPlay binary is not arm64e")
	}
	section := file.Section("__text")
	if section == nil || section.Seg != "__TEXT" {
		return result, fmt.Errorf("FairPlay binary has no __TEXT,__text section")
	}
	text, err := section.Data()
	if err != nil {
		return result, err
	}
	hash, size, err := arm64eMachOHash(path)
	if err != nil {
		return result, err
	}
	patterns, err := fairPlayAnchorPatterns()
	if err != nil {
		return result, err
	}
	operations, tokens, valid := normalizedARM64Operations(text)
	functionRanges, _ := fairPlayFunctionRanges(path, text, section.Addr)
	result = FairPlayBinaryProfile{
		Schema: FairPlayBinaryProfileSchema, SHA256: hash, Bytes: size,
		TextAddress: section.Addr, TextBytes: section.Size,
	}
	accountEntryMatched := false
	codecEvidence := 0
	for _, pattern := range patterns {
		anchor := FairPlayBinaryAnchor{
			Name: pattern.name, ReferenceAddress: pattern.address,
			InstructionCount: len(pattern.operations), PortableBoundary: pattern.portable,
			ExactMatches:      allByteMatches(text, pattern.bytes, section.Addr, 64),
			NormalizedMatches: normalizedOperationMatches(operations, valid, pattern.operations, section.Addr, 64),
		}
		if encoded := fairPlayShapeDefinitions[pattern.name]; encoded != "" {
			shapeBytes, decodeErr := hex.DecodeString(encoded)
			if decodeErr != nil {
				return result, fmt.Errorf("decode FairPlay shape %q: %w", pattern.name, decodeErr)
			}
			shapeOperations, shapeTokens, operationErr := decodeARM64Shape(shapeBytes)
			if operationErr != nil {
				return result, fmt.Errorf("decode FairPlay shape operations %q: %w", pattern.name, operationErr)
			}
			if len(functionRanges) != 0 {
				anchor.ShapeMatches = normalizedFunctionShapeMatches(
					text, shapeOperations, shapeTokens, section.Addr, functionRanges, 8,
				)
			} else {
				anchor.ShapeMatches = normalizedShapeMatches(tokens, valid, shapeTokens, section.Addr, 8)
			}
			if len(anchor.ShapeMatches) != 0 && anchor.ShapeMatches[0].Score >= 0.55 &&
				(len(anchor.ShapeMatches) == 1 || anchor.ShapeMatches[0].Score-anchor.ShapeMatches[1].Score >= 0.08) {
				result.ShapeAnchorCount++
			}
		}
		if len(anchor.ExactMatches) == 1 {
			result.ExactAnchorCount++
		}
		if len(anchor.NormalizedMatches) == 1 {
			result.UniqueAnchorCount++
			accountEntryMatched = accountEntryMatched || pattern.name == "account-entry"
			if pattern.portable {
				result.PortableAnchorCount++
			} else {
				codecEvidence++
			}
		}
		result.Anchors = append(result.Anchors, anchor)
	}
	if result.PortableAnchorCount >= 3 {
		result.StructuralFamily = "macos-current-flattened-v1"
		result.PortableCandidate = true
	} else if accountEntryMatched {
		result.StructuralFamily = "macos-current-account-entry-v1"
	} else if codecEvidence >= 2 {
		result.StructuralFamily = "macos-current-codec-v1"
	}
	return result, nil
}
