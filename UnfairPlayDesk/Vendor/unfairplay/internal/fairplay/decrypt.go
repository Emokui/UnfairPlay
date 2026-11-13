package fairplay

import (
	"archive/zip"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	pageBytes                           = 4096
	minimumARM64InstructionValidPercent = 90
)

type encryptedImage struct {
	member, supfMember, sinfMember string
	sliceOffset                    uint64
	sliceSize                      uint64
	layout                         machoLayout
}

type ipaInventory struct {
	path        string
	bytes       int64
	sha256      string
	sinfMembers []string
	images      []encryptedImage
	supfTables  map[string]supf
	cachedFiles map[string][]byte
}

type DecryptOptions struct {
	InputPath, OutputPath, ReportPath, ModelPath string
	Force                                        bool
	Progress                                     func(OperationProgress)
	verifyOnly                                   bool
}

type DecryptResult struct {
	PlaintextVerified      bool
	OutputPath             string
	OutputSHA256           string
	ReportPath             string
	EncryptedImages        int
	DecryptedPages         int
	LogicalKeySHA256       string
	LogicalKeySHA256BySINF map[string]string
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

func zipBytes(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func adjacentSINF(member string) string {
	return path.Join(path.Dir(member), "SC_Info", path.Base(member)+".sinf")
}

func sinfName(names map[string]bool, member string) (string, error) {
	if candidate := adjacentSINF(member); names[candidate] {
		return candidate, nil
	}
	for directory := path.Dir(member); directory != "." && directory != "/"; directory = path.Dir(directory) {
		prefix := path.Join(directory, "SC_Info") + "/"
		var candidates []string
		for name := range names {
			if strings.HasPrefix(name, prefix) && !strings.Contains(strings.TrimPrefix(name, prefix), "/") && strings.HasSuffix(strings.ToLower(name), ".sinf") {
				candidates = append(candidates, name)
			}
		}
		sort.Strings(candidates)
		if len(candidates) == 1 {
			return candidates[0], nil
		}
		if len(candidates) > 1 {
			return "", fmt.Errorf("encrypted Mach-O %q has ambiguous containing SINFs: %s", member, strings.Join(candidates, ", "))
		}
	}
	return "", fmt.Errorf("encrypted Mach-O %q has no adjacent or containing SINF", member)
}

func supfName(names map[string]bool, member string) string {
	directory := path.Dir(member)
	base := path.Base(member)
	for _, suffix := range []string{".v5.supf", ".supf"} {
		candidate := path.Join(directory, "SC_Info", base+suffix)
		if names[candidate] {
			return candidate
		}
	}
	return ""
}

func readMachOProbe(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	header, err := io.ReadAll(io.LimitReader(reader, 32))
	if err != nil {
		return nil, err
	}
	if len(header) < 4 {
		return header, nil
	}
	magic := binary.LittleEndian.Uint32(header[:4])
	if magic == mhMagic32 || magic == mhMagic64 {
		headerBytes := 28
		if magic == mhMagic64 {
			headerBytes = 32
		}
		if len(header) < headerBytes {
			return header, nil
		}
		commandsBytes := int(binary.LittleEndian.Uint32(header[20:24]))
		required := headerBytes + commandsBytes
		if required < headerBytes || required > 1024*1024 || uint64(required) > file.UncompressedSize64 {
			return header, fmt.Errorf("Mach-O load-command extent is invalid")
		}
		probe := make([]byte, required)
		copy(probe, header)
		if required > len(header) {
			if _, err := io.ReadFull(reader, probe[len(header):]); err != nil {
				return probe, err
			}
		}
		return probe, nil
	}
	if isFatMachO(header) {
		remainder, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		return append(header, remainder...), nil
	}
	return header, nil
}

func openIPAInventory(path string) (ipaInventory, *zip.ReadCloser, error) {
	var result ipaInventory
	abs, err := filepath.Abs(path)
	if err != nil {
		return result, nil, err
	}
	state, err := os.Stat(abs)
	if err != nil {
		return result, nil, err
	}
	result.path = abs
	result.bytes = state.Size()
	result.sha256, err = fileSHA256(abs)
	if err != nil {
		return result, nil, err
	}
	archive, err := zip.OpenReader(abs)
	if err != nil {
		return result, nil, err
	}
	result.supfTables = map[string]supf{}
	result.cachedFiles = map[string][]byte{}
	names := map[string]bool{}
	files := map[string]*zip.File{}
	for _, file := range archive.File {
		if previous, exists := files[file.Name]; exists {
			// Some App Store repacks repeat an empty directory marker. It has no
			// payload to choose between; duplicate files remain ambiguous.
			if strings.HasSuffix(file.Name, "/") && previous.FileInfo().IsDir() &&
				file.FileInfo().IsDir() && previous.UncompressedSize64 == 0 && file.UncompressedSize64 == 0 {
				continue
			}
			archive.Close()
			return result, nil, fmt.Errorf("duplicate IPA member %q", file.Name)
		}
		names[file.Name] = true
		files[file.Name] = file
		if strings.HasSuffix(file.Name, ".sinf") {
			result.sinfMembers = append(result.sinfMembers, file.Name)
		}
	}
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		probe, err := readMachOProbe(file)
		if err != nil {
			archive.Close()
			return result, nil, fmt.Errorf("%s: %w", file.Name, err)
		}
		if len(probe) < 4 {
			continue
		}
		magic := binary.LittleEndian.Uint32(probe[:4])
		if magic != mhMagic32 && magic != mhMagic64 && !isFatMachO(probe) {
			if !isKnownUnsupportedMachO(probe) {
				continue
			}
			archive.Close()
			return result, nil, fmt.Errorf("%s: unsupported Mach-O format; cannot establish complete encryption inventory", file.Name)
		}
		slices, parseErr := parseMachOSlices(probe, file.UncompressedSize64)
		if parseErr != nil {
			archive.Close()
			return result, nil, fmt.Errorf("%s: %w", file.Name, parseErr)
		}
		var encrypted []machoSlice
		for _, slice := range slices {
			if slice.layout.cryptID != 0 {
				encrypted = append(encrypted, slice)
			}
		}
		if len(encrypted) == 0 {
			continue
		}
		if isFatMachO(probe) {
			result.cachedFiles[file.Name] = probe
		}
		supfMember := supfName(names, file.Name)
		if supfMember == "" {
			archive.Close()
			return result, nil, fmt.Errorf("encrypted Mach-O %q has no adjacent SUPF", file.Name)
		}
		sinfMember, err := sinfName(names, file.Name)
		if err != nil {
			archive.Close()
			return result, nil, err
		}
		table, cached := result.supfTables[supfMember]
		if !cached {
			supfBlob, err := zipBytes(files[supfMember])
			if err != nil {
				archive.Close()
				return result, nil, err
			}
			table, err = parseSUPF(supfBlob)
			if err != nil {
				archive.Close()
				return result, nil, err
			}
			result.supfTables[supfMember] = table
		}
		for _, slice := range encrypted {
			records, err := table.recordsFor(slice.layout.cpuType, slice.layout.cpuSubtype)
			if err != nil {
				archive.Close()
				return result, nil, fmt.Errorf("%s: %w", file.Name, err)
			}
			if len(records) != int(slice.layout.cryptSize)/pageBytes {
				archive.Close()
				return result, nil, fmt.Errorf("%s: SUPF page count mismatch for architecture %#x/%#x", file.Name, slice.layout.cpuType, slice.layout.cpuSubtype)
			}
			result.images = append(result.images, encryptedImage{
				member: file.Name, supfMember: supfMember, sinfMember: sinfMember,
				sliceOffset: slice.offset, sliceSize: slice.size, layout: slice.layout,
			})
		}
	}
	if len(result.images) == 0 {
		archive.Close()
		return result, nil, fmt.Errorf("IPA contains no supported encrypted Mach-O images")
	}
	return result, archive, nil
}

func auditARM64(page []byte) (int, map[string]int) {
	counts := map[string]int{}
	valid := 0
	for offset := 0; offset+4 <= len(page); offset += 4 {
		word := binary.LittleEndian.Uint32(page[offset : offset+4])
		if mnemonic, ok := arm64Mnemonic(word); ok {
			valid++
			counts[mnemonic]++
		}
	}
	return valid, counts
}

func arm64Mnemonic(word uint32) (string, bool) {
	if word&0xffe0001f == 0 {
		return "UDF", true
	}
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], word)
	instruction, err := arm64asm.Decode(encoded[:])
	if err == nil {
		return instruction.Op.String(), true
	}
	// x/arch/arm64asm does not currently decode every allocated ARM64 form.
	return supplementalARM64Mnemonic(word)
}

func supplementalARM64Mnemonic(word uint32) (string, bool) {
	switch {
	case word&0x3fa07c00 == 0x08a07c00:
		return "CAS", true // CAS/CASA/CASL/CASAL, byte through 64-bit.
	case word&0xbfa07c00 == 0x08207c00:
		return "CASP", true // CASP/CASPA/CASPL/CASPAL register pairs.
	case word&0x3f200c00 == 0x38200000 && (word>>12)&0xf <= 8:
		operation := [...]string{"LDADD", "LDCLR", "LDEOR", "LDSET", "LDSMAX", "LDSMIN", "LDUMAX", "LDUMIN", "SWP"}[(word>>12)&0xf]
		return operation, true // ARMv8.1 LSE atomic read-modify-write family.
	case word&0xbf80f400 == 0x0f001000:
		return "FMLA", true // FMLA <Vd>.<T>, <Vn>.<T>, <Vm>.H[index]
	case word&0xbfe0fc00 == 0x0e403400:
		return "FMAX", true // FMAX <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	case word&0xbfe0fc00 == 0x0ec03400:
		return "FMIN", true // FMIN <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
	default:
		return "", false
	}
}

type arm64AuditCount struct {
	name  string
	count int
}

func topARM64AuditCounts(counts map[string]int, limit int) string {
	ordered := make([]arm64AuditCount, 0, len(counts))
	for name, count := range counts {
		ordered = append(ordered, arm64AuditCount{name: name, count: count})
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].count != ordered[right].count {
			return ordered[left].count > ordered[right].count
		}
		return ordered[left].name < ordered[right].name
	})
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	parts := make([]string, len(ordered))
	for index, value := range ordered {
		parts[index] = fmt.Sprintf("%s:%d", value.name, value.count)
	}
	return strings.Join(parts, ",")
}

func auditARM64PageDetails(page []byte, pageOffset uint64, ranges []machoFileRange) (map[string]int, map[string]int) {
	mnemonics := make(map[string]int)
	invalid := make(map[string]int)
	pageEnd := pageOffset + uint64(len(page))
	for _, section := range ranges {
		start := max(pageOffset, section.offset)
		end := min(pageEnd, section.offset+section.size)
		start = (start + 3) &^ 3
		end &^= 3
		for cursor := start; cursor+4 <= end; cursor += 4 {
			word := binary.LittleEndian.Uint32(page[cursor-pageOffset : cursor-pageOffset+4])
			if mnemonic, ok := arm64Mnemonic(word); ok {
				mnemonics[mnemonic]++
			} else {
				invalid[fmt.Sprintf("%03x", word>>20)]++
			}
		}
	}
	return mnemonics, invalid
}

func instructionRangesAtPage(pageOffset uint64, ranges []machoFileRange) string {
	pageEnd := pageOffset + pageBytes
	var result []string
	for _, section := range ranges {
		if pageOffset >= section.offset+section.size || pageEnd <= section.offset {
			continue
		}
		name := section.section
		if section.segment != "" {
			name = section.segment + "," + name
		}
		if name == "" {
			name = "unnamed"
		}
		result = append(result, fmt.Sprintf("%s@%#x+%#x/flags=%#x", name, section.offset, section.size, section.flags))
	}
	if len(result) == 0 {
		return "none"
	}
	return strings.Join(result, ";")
}

func instructionRangeContainingPage(pageOffset uint64, ranges []machoFileRange) (machoFileRange, bool) {
	for _, section := range ranges {
		if pageOffset >= section.offset && pageOffset+pageBytes <= section.offset+section.size {
			return section, true
		}
	}
	return machoFileRange{}, false
}

func decryptPagesInPlace(output []byte, image encryptedImage, records [][32]byte, deriver *pageKeyDeriver) ([][16]byte, error) {
	start := int(image.layout.cryptOffset)
	end := start + int(image.layout.cryptSize)
	if start < 0 || end < start || end > len(output) || len(records)*pageBytes != int(image.layout.cryptSize) {
		return nil, fmt.Errorf("%s: encrypted page geometry changed", image.member)
	}
	keys := make([][16]byte, len(records))
	workers := min(runtime.GOMAXPROCS(0), len(records))
	if workers < 1 {
		workers = 1
	}
	if len(records) <= 4 {
		workers = 1
	}
	decryptWorker := func(first int) {
		for index := first; index < len(records); index += workers {
			record := records[index]
			key := deriver.pageKey(
				record[:16], image.sliceOffset+uint64(image.layout.cryptOffset)+uint64(index*pageBytes),
			)
			keys[index] = key
			block, _ := aes.NewCipher(key[:])
			clear(key[:])
			pageStart := start + index*pageBytes
			page := output[pageStart : pageStart+pageBytes]
			cipher.NewCBCDecrypter(block, record[16:]).CryptBlocks(page, page)
		}
	}
	if workers == 1 {
		decryptWorker(0)
	} else {
		var group sync.WaitGroup
		group.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func(first int) { defer group.Done(); decryptWorker(first) }(worker)
		}
		group.Wait()
	}
	return keys, nil
}

func diagnosticARM64Page(start, end int, ranges []machoFileRange) (int, bool) {
	for pass := 0; pass < 2; pass++ {
		for _, section := range ranges {
			if pass == 0 && (section.segment != "__TEXT" || section.section != "__text" || section.flags&sectionAttrPureInstructions == 0) {
				continue
			}
			low := max(uint64(start), section.offset)
			high := min(uint64(end), section.offset+section.size)
			page := (low + pageBytes - 1) &^ uint64(pageBytes-1)
			if page+pageBytes <= high {
				return int(page), true
			}
		}
	}
	return firstARM64AuditPage(start, end, ranges)
}

func pageOffsetAuditTrials(ciphertext []byte, record [32]byte, deriver *pageKeyDeriver, image encryptedImage, pageStart int) string {
	if len(ciphertext) != pageBytes || pageStart < int(image.layout.cryptOffset) {
		return "unavailable"
	}
	pageIndex := (pageStart - int(image.layout.cryptOffset)) / pageBytes
	pageTerm := uint64(pageIndex * pageBytes)
	absolute := image.sliceOffset + uint64(image.layout.cryptOffset) + pageTerm
	type trial struct {
		name         string
		offset       uint64
		littleEndian bool
	}
	trials := []trial{
		{"absolute-per-page", absolute, false},
		{"slice-relative-per-page", uint64(image.layout.cryptOffset) + pageTerm, false},
		{"page-relative", pageTerm, false},
		{"absolute-region-base", image.sliceOffset + uint64(image.layout.cryptOffset), false},
		{"absolute-per-page-le", absolute, true},
	}
	parts := make([]string, 0, len(trials))
	for _, candidate := range trials {
		var key [16]byte
		if candidate.littleEndian {
			var padding [8]byte
			binary.LittleEndian.PutUint64(padding[:], candidate.offset)
			key = deriver.pageKeyWithPadding(record[:16], padding)
		} else {
			key = deriver.pageKey(record[:16], candidate.offset)
		}
		block, _ := aes.NewCipher(key[:])
		scratch := append([]byte(nil), ciphertext...)
		cipher.NewCBCDecrypter(block, record[16:]).CryptBlocks(scratch, scratch)
		valid, words, _ := auditARM64FirstPage(scratch, uint64(pageStart), image.layout.instructionRanges)
		parts = append(parts, fmt.Sprintf("%s=%d/%d", candidate.name, valid, words))
		clear(key[:])
		clear(scratch)
	}
	return strings.Join(parts, ",")
}

func auditARM64StubHelper(data []byte) (int, int, map[string]int) {
	type candidate struct {
		pairs, matched int
	}
	best := candidate{}
	words := len(data) / 4
	for phase := 0; phase < 3; phase++ {
		current := candidate{}
		for index := phase; index+1 < words; index += 3 {
			current.pairs++
			first := binary.LittleEndian.Uint32(data[index*4 : index*4+4])
			second := binary.LittleEndian.Uint32(data[(index+1)*4 : (index+2)*4])
			firstMnemonic, firstValid := arm64Mnemonic(first)
			secondMnemonic, secondValid := arm64Mnemonic(second)
			if firstValid && secondValid && firstMnemonic == "LDR" && secondMnemonic == "B" {
				current.matched++
			}
		}
		if best.pairs == 0 || current.matched*best.pairs > best.matched*current.pairs {
			best = current
		}
	}
	if best.pairs >= 8 && best.matched*100 >= best.pairs*90 {
		return best.matched * 2, best.pairs * 2, map[string]int{"LDR": best.matched, "B": best.matched}
	}
	valid, mnemonics := auditARM64(data)
	return valid, words, mnemonics
}

func auditARM64FirstPage(page []byte, pageOffset uint64, ranges []machoFileRange) (int, int, map[string]int) {
	if len(ranges) == 0 {
		valid, mnemonics := auditARM64(page)
		return valid, len(page) / 4, mnemonics
	}
	pageEnd := pageOffset + uint64(len(page))
	valid, words := 0, 0
	mnemonics := make(map[string]int)
	for _, section := range ranges {
		start := max(pageOffset, section.offset)
		end := min(pageEnd, section.offset+section.size)
		start = (start + 3) &^ 3
		end &^= 3
		if start >= end {
			continue
		}
		data := page[start-pageOffset : end-pageOffset]
		observed, sectionWords, counts := 0, 0, map[string]int(nil)
		if section.segment == "__TEXT" && section.section == "__stub_helper" {
			observed, sectionWords, counts = auditARM64StubHelper(data)
		} else {
			observed, counts = auditARM64(data)
			sectionWords = len(data) / 4
		}
		valid += observed
		words += sectionWords
		for mnemonic, count := range counts {
			mnemonics[mnemonic] += count
		}
	}
	return valid, words, mnemonics
}

func firstARM64AuditPage(start, end int, ranges []machoFileRange) (int, bool) {
	if len(ranges) == 0 {
		return start, start >= 0 && start+pageBytes <= end
	}
	result := end
	for _, section := range ranges {
		intersection := max(uint64(start), section.offset)
		intersectionEnd := min(uint64(end), section.offset+section.size)
		if intersection >= intersectionEnd {
			continue
		}
		page := int(intersection) &^ (pageBytes - 1)
		if page < start {
			page = start
		}
		if page+pageBytes <= end && page < result {
			result = page
		}
	}
	return result, result != end
}

func auditAdditionalARM64Pages(output []byte, start, count, auditedIndex int, ranges []machoFileRange) error {
	var candidates []int
	for index := 0; index < count; index++ {
		if index == auditedIndex {
			continue
		}
		pageStart := uint64(start + index*pageBytes)
		for _, section := range ranges {
			if pageStart >= section.offset && pageStart+pageBytes <= section.offset+section.size {
				candidates = append(candidates, index)
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	checked := map[int]bool{}
	plausible := 0
	var details []string
	for _, position := range []int{0, len(candidates) / 2, len(candidates) - 1} {
		index := candidates[position]
		if checked[index] {
			continue
		}
		checked[index] = true
		pageStart := start + index*pageBytes
		valid, words, _ := auditARM64FirstPage(output[pageStart:pageStart+pageBytes], uint64(pageStart), ranges)
		details = append(details, fmt.Sprintf("%#x=%d/%d[%s]", pageStart, valid, words, instructionRangesAtPage(uint64(pageStart), ranges)))
		if words != 0 && valid*100 >= words*minimumARM64InstructionValidPercent {
			plausible++
		}
	}
	if plausible*2 < len(checked)+1 {
		return fmt.Errorf("additional executable pages failed ARM64 structural audit (%d/%d sampled pages plausible; pages=%s)", plausible, len(checked), strings.Join(details, ","))
	}
	return nil
}

func decryptImage(output []byte, image encryptedImage, records [][32]byte, mask [16]byte, deriver *pageKeyDeriver) (*imageReport, error) {
	if image.layout.cryptID != 1 {
		return nil, fmt.Errorf("%s: expected cryptid 1", image.member)
	}
	start := int(image.layout.cryptOffset)
	end := start + int(image.layout.cryptSize)
	id := image.layout.cryptIDOffset
	if id < 0 || id+4 > start || start < 0 || end < start || end > len(output) {
		return nil, fmt.Errorf("%s: invalid FairPlay mutation ranges", image.member)
	}
	encryptedDigest := sha256.Sum256(output)
	prefixDigest := sha256.Sum256(output[:id])
	headerDigest := sha256.Sum256(output[id+4 : start])
	suffixDigest := sha256.Sum256(output[end:])
	audits, err := auditCodeDirectories(output, image.layout)
	if err != nil {
		return nil, err
	}
	for _, audit := range audits {
		if audit.MatchedSlots != audit.SlotCount {
			return nil, fmt.Errorf("%s: encrypted source fails CodeDirectory", image.member)
		}
	}
	diagnosticPageStart, hasDiagnosticPage := 0, false
	var diagnosticCiphertext []byte
	if isARM64InstructionSet(image.layout.cpuType) {
		diagnosticPageStart, hasDiagnosticPage = diagnosticARM64Page(start, end, image.layout.instructionRanges)
		if hasDiagnosticPage && diagnosticPageStart >= start && diagnosticPageStart+pageBytes <= end {
			diagnosticCiphertext = append([]byte(nil), output[diagnosticPageStart:diagnosticPageStart+pageBytes]...)
			defer clear(diagnosticCiphertext)
		}
	}
	keys, err := decryptPagesInPlace(output, image, records, deriver)
	if err != nil {
		return nil, err
	}
	keysHash := sha256.New()
	for _, key := range keys {
		keysHash.Write(key[:])
	}
	clear(keys)
	// Independent pre-encryption hashes validate bytes even when executable
	// sections contain inline data or SDK protection. Restore cryptid only
	// for this comparison; normal mutation-scope checks still run below.
	binary.LittleEndian.PutUint32(output[id:id+4], 0)
	plaintextAudits, plaintextErr := auditPreEncryptionCodeDirectories(output, image.layout)
	binary.LittleEndian.PutUint32(output[id:id+4], image.layout.cryptID)
	if plaintextErr != nil {
		return nil, fmt.Errorf("%s: validate plaintext hashes: %w", image.member, plaintextErr)
	}
	for _, audit := range plaintextAudits {
		if audit.MatchedSlots != audit.SlotCount {
			return nil, fmt.Errorf("%s: plaintext page hash mismatch (%d/%d)", image.member, audit.MatchedSlots, audit.SlotCount)
		}
	}
	plaintextVerified := len(plaintextAudits) != 0
	auditPageStart := start
	valid, instructionWords, mnemonics := 0, 0, map[string]int(nil)
	structurallyPlausible := false
	if isARM64InstructionSet(image.layout.cpuType) && !plaintextVerified {
		bestValid, bestWords, bestStart := 0, 0, start
		bestFullValid, bestFullWords, bestFullStart := 0, 0, 0
		if len(image.layout.instructionRanges) == 0 {
			valid, mnemonics = auditARM64(output[start : start+pageBytes])
			instructionWords = pageBytes / 4
			bestValid, bestWords = valid, instructionWords
			structurallyPlausible = valid*100 >= instructionWords*minimumARM64InstructionValidPercent
		} else {
			firstCandidate, hasSections := firstARM64AuditPage(start, end, image.layout.instructionRanges)
			if !hasSections {
				return nil, fmt.Errorf("%s: encrypted region has no executable ARM64 instructions to audit", image.member)
			}
			for candidate := firstCandidate; !structurallyPlausible && candidate+pageBytes <= end; candidate += pageBytes {
				observed, words, counts := auditARM64FirstPage(
					output[candidate:candidate+pageBytes], uint64(candidate), image.layout.instructionRanges,
				)
				if words == 0 {
					continue
				}
				if bestWords == 0 || observed*bestWords > bestValid*words {
					bestValid, bestWords, bestStart = observed, words, candidate
				}
				if _, full := instructionRangeContainingPage(uint64(candidate), image.layout.instructionRanges); full &&
					(bestFullWords == 0 || observed*bestFullWords > bestFullValid*words) {
					bestFullValid, bestFullWords, bestFullStart = observed, words, candidate
				}
				if observed*100 >= words*minimumARM64InstructionValidPercent {
					auditPageStart = candidate
					valid, instructionWords, mnemonics = observed, words, counts
					structurallyPlausible = true
					break
				}
			}
		}
		if !structurallyPlausible {
			best := output[bestStart : bestStart+pageBytes]
			mnemonics, invalid := auditARM64PageDetails(best, uint64(bestStart), image.layout.instructionRanges)
			fullPage := "none"
			if bestFullWords != 0 {
				fullPage = fmt.Sprintf("%d/%d@%#x[%s]", bestFullValid, bestFullWords, bestFullStart,
					instructionRangesAtPage(uint64(bestFullStart), image.layout.instructionRanges))
			}
			trials := "unavailable"
			if len(diagnosticCiphertext) == pageBytes {
				index := (diagnosticPageStart - start) / pageBytes
				if index >= 0 && index < len(records) {
					trials = pageOffsetAuditTrials(diagnosticCiphertext, records[index], deriver, image, diagnosticPageStart)
				}
			}
			return nil, fmt.Errorf("%s: best executable page has only %d/%d valid ARM64 words (SHA-256 %s); audit page=%#x ranges=[%s] full-page=%s mnemonics=[%s] invalid-classes=[%s] offset-trials=[%s]",
				image.member, bestValid, bestWords, digest(best), bestStart,
				instructionRangesAtPage(uint64(bestStart), image.layout.instructionRanges), fullPage,
				topARM64AuditCounts(mnemonics, 8), topARM64AuditCounts(invalid, 8), trials)
		}
		auditedPageIndex := (auditPageStart - start) / pageBytes
		if err := auditAdditionalARM64Pages(output, start, len(records), auditedPageIndex, image.layout.instructionRanges); err != nil {
			return nil, fmt.Errorf("%s: %w", image.member, err)
		}
	}
	auditedPageIndex := (auditPageStart - start) / pageBytes
	first := output[auditPageStart : auditPageStart+pageBytes]
	binary.LittleEndian.PutUint32(output[id:id+4], 0)
	if sha256.Sum256(output[:id]) != prefixDigest ||
		sha256.Sum256(output[id+4:start]) != headerDigest ||
		sha256.Sum256(output[end:]) != suffixDigest {
		return nil, fmt.Errorf("%s: mutation escaped FairPlay range", image.member)
	}
	decryptedDigest := sha256.Sum256(output)
	report := &imageReport{
		Member: image.member, SUPFMember: image.supfMember,
		Architecture: machoArchitecture(image.layout.cpuType, image.layout.cpuSubtype), CPUType: image.layout.cpuType, CPUSubtype: image.layout.cpuSubtype,
		SliceOffset: image.sliceOffset, SliceSize: image.sliceSize,
		EncryptedSHA256: hex.EncodeToString(encryptedDigest[:]), DecryptedSHA256: hex.EncodeToString(decryptedDigest[:]),
		CryptOffset: image.layout.cryptOffset, CryptSize: image.layout.cryptSize, Pages: len(records),
		FirstPlaintextPageSHA256: digest(first), AuditedPageIndex: auditedPageIndex, FirstPageValidARM64Words: valid,
		FirstPageStructurallyPlausible: structurallyPlausible, FirstPageMnemonics: mnemonics,
		OrderedPageKeysSHA256: hex.EncodeToString(keysHash.Sum(nil)), AppMaskSHA256: digest(mask[:]),
		PreEncryptionCodeDirectories: plaintextAudits,
		CodeDirectories:              audits, CryptIDBefore: 1, CryptIDAfter: 0, ExactMutationScope: true,
	}
	if plaintextVerified {
		report.FirstPageAudit = "code-directory-pre-encryption-hashes"
	} else if isARM64InstructionSet(image.layout.cpuType) {
		report.FirstPageAudit = "arm64-instruction-decode"
		if auditedPageIndex != 0 {
			report.FirstPageAudit = "arm64-first-executable-page-instruction-decode"
		}
		report.FirstPageInstructionWords = instructionWords
	} else {
		report.FirstPageAudit = "not-performed"
	}
	return report, nil
}

func validateInventoriedImages(blob []byte, images []encryptedImage) error {
	if len(images) == 0 {
		return fmt.Errorf("encrypted image inventory is empty")
	}
	slices, err := parseMachOSlices(blob, uint64(len(blob)))
	if err != nil {
		return err
	}
	encrypted := make([]machoSlice, 0, len(slices))
	for _, slice := range slices {
		if slice.layout.cryptID != 0 {
			encrypted = append(encrypted, slice)
		}
	}
	if len(encrypted) != len(images) {
		return fmt.Errorf("encrypted slice inventory changed")
	}
	for index, slice := range encrypted {
		image := images[index]
		if slice.offset != image.sliceOffset || slice.size != image.sliceSize || !sameMachoLayout(slice.layout, image.layout) {
			return fmt.Errorf("encrypted slice %d changed after inventory", index)
		}
	}
	return nil
}

func stagePrivateJSON(path string, value any) (string, error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".fairplay-*.json")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	complete := false
	defer func() {
		temporary.Close()
		if !complete {
			os.Remove(name)
		}
	}()
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	complete = true
	return name, nil
}

// VerifyIPA runs the same complete image/key/plaintext validation without
// compressing, writing or retaining an output IPA or report.
func VerifyIPA(options DecryptOptions) (DecryptResult, error) {
	options.verifyOnly = true
	return DecryptIPA(options)
}

func DecryptIPA(options DecryptOptions) (DecryptResult, error) {
	started := time.Now()
	emit := func(phase, message string, done, total int) {
		if options.Progress != nil {
			options.Progress(OperationProgress{Phase: phase, Message: message, Completed: done, Total: total, ElapsedMS: time.Since(started).Milliseconds()})
		}
	}
	emit("inventory", "正在检查 IPA 与加密镜像", 0, 0)
	var result DecryptResult
	if err := checkPlatform(); err != nil {
		return result, err
	}
	options, err := validatePaths(options)
	if err != nil {
		return result, err
	}
	for _, path := range []string{options.OutputPath, options.ReportPath} {
		if options.verifyOnly {
			break
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return result, err
		}
	}
	inventory, source, err := openIPAInventory(options.InputPath)
	if err != nil {
		return result, err
	}
	defer source.Close()
	files := map[string]*zip.File{}
	for _, file := range source.File {
		files[file.Name] = file
	}
	emit("licenses", "正在解析模型与应用许可", 0, 0)
	licenses, licenseReports, err := resolveIPALicenses(inventory, files, options.ModelPath)
	if err != nil {
		return result, err
	}
	defer func() {
		for _, license := range licenses {
			clear(license.material.LogicalKey[:])
			clear(license.mask[:])
		}
	}()
	keyHashes := make(map[string]string, len(licenseReports))
	sharedKeyHash, providerName, modelName := "", "", ""
	for index, license := range licenseReports {
		keyHashes[license.Member] = license.LogicalKeySHA256
		if index == 0 {
			sharedKeyHash, providerName, modelName = license.LogicalKeySHA256, license.Provider, license.ModelBuild
			continue
		}
		if sharedKeyHash != license.LogicalKeySHA256 {
			sharedKeyHash = ""
		}
		if providerName != license.Provider {
			providerName = "multiple"
		}
		if modelName != license.ModelBuild {
			modelName = "multiple"
		}
	}
	oracle := map[string]any{"request_ipa_sha256": inventory.sha256}
	if len(licenseReports) == 1 {
		oracle = licenseReports[0].Oracle
	}
	imageMap := map[string][]encryptedImage{}
	for _, image := range inventory.images {
		imageMap[image.member] = append(imageMap[image.member], image)
	}
	var temporary *os.File
	var writer *zip.Writer
	var tempName string
	outputHasher := sha256.New()
	if !options.verifyOnly {
		temporary, err = os.CreateTemp(filepath.Dir(options.OutputPath), ".fairplay-*.ipa")
		if err != nil {
			return result, err
		}
		tempName = temporary.Name()
		defer os.Remove(tempName)
		defer temporary.Close()
		writer = zip.NewWriter(io.MultiWriter(temporary, outputHasher))
		// The archive is written sequentially. Reuse its compressor between
		// changed Mach-O members; unchanged resources still use raw ZIP Copy.
		var compressor *flate.Writer
		writer.RegisterCompressor(zip.Deflate, func(dst io.Writer) (io.WriteCloser, error) {
			if compressor == nil {
				var err error
				compressor, err = flate.NewWriter(dst, 3)
				if err != nil {
					return nil, err
				}
			} else {
				compressor.Reset(dst)
			}
			return compressor, nil
		})
	}
	var imageReports []*imageReport
	pages := 0
	seenDirectories := map[string]bool{}
	for _, file := range source.File {
		if file.FileInfo().IsDir() {
			if seenDirectories[file.Name] {
				continue // Duplicate empty directory markers were checked during inventory.
			}
			seenDirectories[file.Name] = true
		}
		images, encrypted := imageMap[file.Name]
		if !encrypted {
			if writer != nil {
				if err := writer.Copy(file); err != nil {
					return result, err
				}
			}
			continue
		}
		blob, cached := inventory.cachedFiles[file.Name]
		if !cached {
			blob, err = zipBytes(file)
			if err != nil {
				return result, err
			}
		}
		if err := validateInventoriedImages(blob, images); err != nil {
			return result, fmt.Errorf("%s: %w", file.Name, err)
		}
		table, ok := inventory.supfTables[images[0].supfMember]
		if !ok {
			return result, fmt.Errorf("%s: inventoried SUPF is unavailable", file.Name)
		}
		var target io.Writer
		if writer != nil {
			header := file.FileHeader
			target, err = writer.CreateHeader(&header)
			if err != nil {
				return result, err
			}
		}
		license := licenses[images[0].sinfMember]
		for _, image := range images {
			emit("images", "正在解密并校验可执行镜像", len(imageReports), len(inventory.images))
			end := image.sliceOffset + image.sliceSize
			if end < image.sliceOffset || end > uint64(len(blob)) {
				return result, fmt.Errorf("%s slice changed after inventory", image.member)
			}
			records, err := table.recordsFor(image.layout.cpuType, image.layout.cpuSubtype)
			if err != nil {
				return result, err
			}
			report, err := decryptImage(blob[image.sliceOffset:end], image, records, license.mask, license.deriver)
			if err != nil {
				return result, err
			}
			report.SINFMember = image.sinfMember
			imageReports = append(imageReports, report)
			pages += len(records)
		}
		if target != nil {
			emit("packing", "正在打包已解密镜像", len(imageReports), len(inventory.images))
			if _, err := target.Write(blob); err != nil {
				return result, err
			}
		}
	}
	plaintextVerified := len(imageReports) != 0
	for _, image := range imageReports {
		if len(image.PreEncryptionCodeDirectories) == 0 {
			plaintextVerified = false
		}
	}
	result = DecryptResult{EncryptedImages: len(imageReports), DecryptedPages: pages, PlaintextVerified: plaintextVerified, LogicalKeySHA256: sharedKeyHash, LogicalKeySHA256BySINF: keyHashes}
	if options.verifyOnly {
		emit("complete", "全部加密镜像验证完成", len(imageReports), len(inventory.images))
		return result, nil
	}
	emit("saving", "正在完成输出文件", len(imageReports), len(inventory.images))
	if err := writer.Close(); err != nil {
		return result, err
	}
	if err := temporary.Sync(); err != nil {
		return result, err
	}
	if err := temporary.Close(); err != nil {
		return result, err
	}
	outputHash := hex.EncodeToString(outputHasher.Sum(nil))
	report := decryptionReport{
		Schema: "unfairplay-decryption-v1", ModelBuild: modelName,
		Input:    reportFile{Path: inventory.path, Bytes: inventory.bytes, SHA256: inventory.sha256},
		Output:   reportFile{Path: options.OutputPath, SHA256: outputHash, Mode: "0600"},
		Provider: providerName, Oracle: oracle, Licenses: licenseReports,
		EncryptedImages: len(imageReports), DecryptedPages: pages, Images: imageReports,
		Complete:          len(imageReports) == len(inventory.images),
		PlaintextVerified: plaintextVerified,
		Warnings:          decryptionWarnings(plaintextVerified),
	}
	reportTemp, err := stagePrivateJSON(options.ReportPath, report)
	if err != nil {
		return result, err
	}
	defer os.Remove(reportTemp)
	if _, err := validatePaths(options); err != nil {
		return result, err
	}
	if err := publishFiles([]stagedFile{{tempName, options.OutputPath}, {reportTemp, options.ReportPath}}, options.Force); err != nil {
		return result, err
	}
	result = DecryptResult{
		OutputPath: options.OutputPath, OutputSHA256: outputHash, ReportPath: options.ReportPath, PlaintextVerified: plaintextVerified,
		EncryptedImages: len(imageReports), DecryptedPages: pages,
		LogicalKeySHA256: sharedKeyHash, LogicalKeySHA256BySINF: keyHashes,
	}
	emit("complete", "解密与保存完成", len(imageReports), len(inventory.images))
	return result, nil
}
