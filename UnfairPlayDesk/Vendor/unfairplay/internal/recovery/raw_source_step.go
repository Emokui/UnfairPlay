package recovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

var rawSourceBinaryHash = [32]byte{0x1e, 0x58, 0xd3, 0x7e, 0x96, 0x02, 0xdd, 0x0c, 0xa5, 0xe2, 0x4b, 0x14, 0x76, 0x20, 0x63, 0xb6, 0xc3, 0x10, 0x24, 0x8b, 0x4d, 0x3a, 0x94, 0x27, 0x27, 0x71, 0xd8, 0x15, 0xe4, 0xea, 0x17, 0x84}

var lastRawSourceState *state

type rawSourceOpenFile struct {
	data   []byte
	offset uint64
}

type rawSourceCFValue struct {
	kind string
	data []byte
	flag bool
}

type rawSourceRuntime struct {
	files            map[string][]byte
	openFiles        map[uint64]*rawSourceOpenFile
	nextFD           uint64
	nextAllocation   uint64
	mac              []byte
	onceTokens       map[uint64]bool
	nextIOIterator   uint32
	nextIOService    uint32
	iteratorServices map[uint32]uint32
	fakeCFValues     map[uint64]rawSourceCFValue
	stopPC           uint64
}

var activeRawSourceRuntime *rawSourceRuntime

const rawSourceErrnoAddress = uint64(0x7100FFF00000)

func configureRawSourceRuntime(value *model, kernel string, fileSpecs []string, macPath, executablePath string, stopPC uint64) error {
	runtimeKernel := kernel == "account-cfg" || kernel == "enrollment-full" || kernel == "enrollment-frame" || kernel == "enrollment-sinf" || kernel == "bootstrap-cfg" || kernel == "bootstrap-full"
	if !runtimeKernel {
		if len(fileSpecs) != 0 || macPath != "" || executablePath != "" || stopPC != 0 {
			return fmt.Errorf("raw source runtime inputs require an account or bootstrap CFG kernel")
		}
		activeRawSourceRuntime = nil
		return nil
	}
	profile, err := executionProfileForModel(value)
	if err != nil {
		return err
	}
	runtime := &rawSourceRuntime{
		files:            make(map[string][]byte),
		openFiles:        make(map[uint64]*rawSourceOpenFile),
		nextFD:           100,
		nextAllocation:   0x710100000000,
		onceTokens:       make(map[uint64]bool, len(profile.onceTokens)),
		nextIOIterator:   0x100,
		nextIOService:    0x200,
		iteratorServices: make(map[uint32]uint32),
		fakeCFValues:     make(map[uint64]rawSourceCFValue),
		stopPC:           stopPC,
	}
	for _, token := range profile.onceTokens {
		runtime.onceTokens[token] = true
	}
	var maxStaticAllocation uint64
	for address := range value.pages {
		if address >= 0x700010000000 && address < 0x700020000000 && address > maxStaticAllocation {
			maxStaticAllocation = address
		}
	}
	if maxStaticAllocation != 0 {
		runtime.nextAllocation = (maxStaticAllocation + 0x100000) &^ 0xFFFFF
	}
	accountKernel := kernel == "account-cfg" || kernel == "enrollment-full" || kernel == "enrollment-frame" || kernel == "enrollment-sinf"
	if accountKernel {
		if executablePath == "" || len(executablePath) >= int(pageSize) {
			return fmt.Errorf("account-entry parser requires a bounded installed executable path")
		}
		if err := value.patch(0x700000200000, append([]byte(executablePath), 0)); err != nil {
			return err
		}
	} else if executablePath != "" {
		return fmt.Errorf("installed executable path is only valid with an account CFG kernel")
	}
	if _, ok := value.pages[rawSourceErrnoAddress]; !ok {
		value.pages[rawSourceErrnoAddress] = make([]byte, pageSize)
	}
	for _, specification := range fileSpecs {
		suffix, path, ok := strings.Cut(specification, "=")
		if !ok || suffix == "" || path == "" {
			return fmt.Errorf("invalid raw source file mapping %q", specification)
		}
		data, err := readPrivateInput(path)
		if err != nil {
			return fmt.Errorf("read raw source file %q: %w", path, err)
		}
		if _, exists := runtime.files[suffix]; exists {
			return fmt.Errorf("duplicate raw source file mapping %q", suffix)
		}
		runtime.files[suffix] = data
	}
	if macPath != "" {
		mac, err := readPrivateInput(macPath)
		if err != nil {
			return err
		}
		if len(mac) != 6 {
			encoded := strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(string(mac)))
			mac, err = hex.DecodeString(encoded)
		}
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("raw source hardware address must contain six bytes")
		}
		runtime.mac = mac
	}
	activeRawSourceRuntime = runtime
	return nil
}

func (r *rawSourceRuntime) allocate(s *state, size uint64) (uint64, error) {
	if size > 0x10000000 {
		return 0, fmt.Errorf("invalid bootstrap allocation size %#x", size)
	}
	address := r.nextAllocation
	r.nextAllocation += 0x100000
	mapped := (max(size, 1) + pageSize - 1) &^ (pageSize - 1)
	if mapped < 0x100000 {
		mapped = 0x100000
	}
	if err := s.mapZero(address, mapped); err != nil {
		return 0, err
	}
	return address, nil
}

func (r *rawSourceRuntime) matchingFile(path string) (string, []byte, bool) {
	bestSuffix := ""
	var bestData []byte
	for suffix, data := range r.files {
		if strings.HasSuffix(path, suffix) && len(suffix) > len(bestSuffix) {
			bestSuffix, bestData = suffix, data
		}
	}
	return bestSuffix, bestData, bestSuffix != ""
}

func (r *rawSourceRuntime) writeStat(s *state, address uint64, size int) error {
	data := make([]byte, 144)
	binary.LittleEndian.PutUint16(data[4:6], 0o100644)
	binary.LittleEndian.PutUint16(data[6:8], 1)
	binary.LittleEndian.PutUint64(data[96:104], uint64(size))
	return s.store(address, data)
}

func (r *rawSourceRuntime) setErrno(s *state, value uint32) error {
	return s.storeValue(rawSourceErrnoAddress, uint64(value), 4)
}

func (r *rawSourceRuntime) handle(s *state, pc uint64) (uint64, error) {
	returnAddress := s.x[30]
	switch pc {
	case 0xF100000000006000: // free
	case 0xF1000000000E4000: // chkstk_darwin
	case 0xF100000000007000: // malloc
		address, err := r.allocate(s, s.x[0])
		if err != nil {
			return pc, err
		}
		s.x[0] = address
	case 0xF10000000001F000: // open
		path, err := s.readCString(s.x[0], 0x100000)
		if err != nil {
			return pc, err
		}
		_, data, ok := r.matchingFile(path)
		if !ok {
			if err := r.setErrno(s, 2); err != nil {
				return pc, err
			}
			s.x[0] = 0xFFFFFFFF
			break
		}
		fd := r.nextFD
		r.nextFD++
		r.openFiles[fd] = &rawSourceOpenFile{data: data}
		s.x[0] = fd
	case 0xF10000000004D000: // fstat
		entry := r.openFiles[s.x[0]]
		if entry == nil {
			if err := r.setErrno(s, 9); err != nil {
				return pc, err
			}
			s.x[0] = 0xFFFFFFFF
			break
		}
		if err := r.writeStat(s, s.x[1], len(entry.data)); err != nil {
			return pc, err
		}
		s.x[0] = 0
	case 0xF100000000023000: // mmap
		entry := r.openFiles[s.x[4]]
		if entry == nil {
			s.x[0] = ^uint64(0)
			break
		}
		length := s.x[1]
		accessibleLength := (length + 0x3FFF) &^ 0x3FFF
		address, err := r.allocate(s, length)
		if err != nil {
			return pc, err
		}
		start := min(s.x[5], uint64(len(entry.data)))
		end := min(start+accessibleLength, uint64(len(entry.data)))
		if err := s.store(address, entry.data[start:end]); err != nil {
			return pc, err
		}
		s.x[0] = address
	case 0xF100000000050000: // munmap
		s.x[0] = 0
	case 0xF10000000001A000: // close
		delete(r.openFiles, s.x[0])
		s.x[0] = 0
	case 0xF10000000006E000: // lstat
		path, err := s.readCString(s.x[0], 0x100000)
		if err != nil {
			return pc, err
		}
		_, data, ok := r.matchingFile(path)
		if !ok {
			if err := r.setErrno(s, 2); err != nil {
				return pc, err
			}
			s.x[0] = 0xFFFFFFFF
			break
		}
		if err := r.writeStat(s, s.x[1], len(data)); err != nil {
			return pc, err
		}
		s.x[0] = 0
	case 0xF100000000008000: // read
		entry := r.openFiles[s.x[0]]
		if entry == nil {
			if err := r.setErrno(s, 9); err != nil {
				return pc, err
			}
			s.x[0] = 0xFFFFFFFF
			break
		}
		count := min(s.x[2], uint64(0x10000000))
		start := min(entry.offset, uint64(len(entry.data)))
		end := min(start+count, uint64(len(entry.data)))
		if err := s.store(s.x[1], entry.data[start:end]); err != nil {
			return pc, err
		}
		entry.offset = end
		s.x[0] = end - start
	case 0xF10000000001B000: // __error
		s.x[0] = rawSourceErrnoAddress
	case 0xF100000000003000: // gettimeofday
		if s.x[0] != 0 {
			if err := s.storeValue(s.x[0], 1_700_000_000, 8); err != nil {
				return pc, err
			}
			if err := s.storeValue(s.x[0]+8, 0, 8); err != nil {
				return pc, err
			}
		}
		s.x[0] = 0
	case 0xF10000000002F000: // IOMainPort
		if s.x[1] != 0 {
			if err := s.storeValue(s.x[1], 1, 4); err != nil {
				return pc, err
			}
		}
		s.x[0] = 0
	case 0xF1000000000A1000: // IOBSDNameMatching
		s.x[0] = 0x710200000000
	case 0xF100000000043000: // IOServiceGetMatchingServices
		iterator := r.nextIOIterator
		r.nextIOIterator++
		service := r.nextIOService
		r.nextIOService++
		r.iteratorServices[iterator] = service
		if err := s.storeValue(s.x[2], uint64(iterator), 4); err != nil {
			return pc, err
		}
		s.x[0] = 0
	case 0xF10000000002C000: // IOIteratorNext
		iterator := uint32(s.x[0])
		s.x[0] = uint64(r.iteratorServices[iterator])
		delete(r.iteratorServices, iterator)
	case 0xF10000000004E000: // IORegistryEntryCreateCFProperty
		keyPointer, err := s.load(s.x[1]+16, 8)
		if err != nil {
			return pc, err
		}
		keyLength, err := s.load(s.x[1]+24, 8)
		if err != nil || keyLength > 0x1000 {
			return pc, fmt.Errorf("invalid IOKit property key")
		}
		keyBytes, err := s.outputBytes(keyPointer, int(keyLength))
		if err != nil {
			return pc, err
		}
		valueAddress, err := r.allocate(s, 1)
		if err != nil {
			return pc, err
		}
		switch string(keyBytes) {
		case "IOBuiltin":
			r.fakeCFValues[valueAddress] = rawSourceCFValue{kind: "boolean", flag: true}
		case "IOMACAddress":
			if len(r.mac) != 6 {
				return pc, fmt.Errorf("bootstrap CFG requires --raw-source-mac")
			}
			r.fakeCFValues[valueAddress] = rawSourceCFValue{kind: "data", data: append([]byte(nil), r.mac...)}
		default:
			return pc, fmt.Errorf("unsupported IOKit property %q", keyBytes)
		}
		s.x[0] = valueAddress
	case 0xF10000000000C000: // CFBooleanGetValue
		value, ok := r.fakeCFValues[s.x[0]]
		if !ok || value.kind != "boolean" {
			return pc, fmt.Errorf("invalid modeled CFBoolean")
		}
		if value.flag {
			s.x[0] = 1
		} else {
			s.x[0] = 0
		}
	case 0xF100000000019000: // CFRelease
		delete(r.fakeCFValues, s.x[0])
	case 0xF1000000000A2000: // IORegistryEntryGetParentEntry
		parent := r.nextIOService
		r.nextIOService++
		if err := s.storeValue(s.x[2], uint64(parent), 4); err != nil {
			return pc, err
		}
		s.x[0] = 0
	case 0xF10000000007C000: // CFDataGetBytes
		value, ok := r.fakeCFValues[s.x[0]]
		if !ok || value.kind != "data" {
			return pc, fmt.Errorf("invalid modeled CFData")
		}
		start := min(s.x[1], uint64(len(value.data)))
		end := min(start+s.x[2], uint64(len(value.data)))
		if err := s.store(s.x[3], value.data[start:end]); err != nil {
			return pc, err
		}
	case 0xF100000000034000: // IOObjectRelease
		s.x[0] = 0
	case 0xF100000000025000: // pthread_once
		token := s.x[0]
		if r.onceTokens[token] {
			// The private reference runner models pthread_once with a tiny
			// AArch64 stub.  Preserve its otherwise-dead stack spill so a
			// checkpoint comparison remains byte-exact as well as
			// architecturally exact across the external call.
			stubStack := s.sp - 16
			if err := s.storeValue(stubStack, s.x[29], 8); err != nil {
				return pc, err
			}
			if err := s.storeValue(stubStack+8, s.x[30], 8); err != nil {
				return pc, err
			}
			s.x[1] = 0x720000000000
			s.x[0] = 0
		} else {
			r.onceTokens[token] = true
		}
	case 0xF10000000002500C: // initialized pthread_once callback
	case 0x720000000000: // initialized pthread_once callback
	case 0xF10000000000E000, // pthread_rwlock_unlock
		0xF100000000040000, // pthread_rwlock_rdlock
		0xF10000000005C000, // pthread_rwlock_init
		0xF100000000065000: // pthread_rwlock_wrlock
		s.x[0] = 0
	default:
		return pc, fmt.Errorf("unsupported bootstrap external %#x", pc)
	}
	return returnAddress, nil
}

func runRawSource(value *model, kernel string, loop bool, exactIterations int) (string, int, error) {
	profile, err := executionProfileForModel(value)
	if err != nil {
		return "", 0, err
	}
	if value.binaryHash != profile.binaryHash {
		return "", 0, fmt.Errorf("raw source model does not match generated fairplayd build")
	}
	worker := newState(value)
	worker.reset()
	lastRawSourceState = worker
	if kernel == "enrollment-full" {
		if loop || exactIterations != 0 {
			return "", 0, fmt.Errorf("enrollment-full owns its complete natural loop")
		}
		if _, _, err := runRawSourceAccountEntryCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		if _, _, err := runRawSourceBootstrapCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		iterations, err := runRawSourceKernelLoop(worker, "outer")
		if err != nil {
			return "", iterations, err
		}
		return worker.digest(), iterations, nil
	}
	if kernel == "enrollment-frame" {
		if loop || exactIterations != 0 {
			return "", 0, fmt.Errorf("enrollment-frame owns its complete natural path")
		}
		if _, _, err := runRawSourceAccountEntryCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		if _, _, err := runRawSourceBootstrapCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		iterations, err := runRawSourceKernelLoop(worker, "outer")
		if err != nil {
			return "", iterations, err
		}
		if _, _, err := runRawSourceSelectionCFG(worker, activeRawSourceRuntime, value.selectionMaxBlocks); err != nil {
			return "", iterations, err
		}
		return worker.digest(), iterations, nil
	}
	if kernel == "enrollment-sinf" {
		if loop || exactIterations != 0 {
			return "", 0, fmt.Errorf("enrollment-sinf owns its complete natural path")
		}
		if _, _, err := runRawSourceAccountEntryCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		if _, _, err := runRawSourceBootstrapCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		iterations, err := runRawSourceKernelLoop(worker, "outer")
		if err != nil {
			return "", iterations, err
		}
		if _, _, err := runRawSourceSelectionCFG(worker, activeRawSourceRuntime, value.selectionMaxBlocks); err != nil {
			return "", iterations, err
		}
		if _, _, err := runRawSourceSINFEntryCFG(worker, activeRawSourceRuntime, 2_000_000); err != nil {
			return "", iterations, err
		}
		return worker.digest(), iterations, nil
	}
	if kernel == "bootstrap-full" {
		if loop || exactIterations != 0 {
			return "", 0, fmt.Errorf("bootstrap-full owns its complete natural loop")
		}
		if _, _, err := runRawSourceBootstrapCFG(worker, activeRawSourceRuntime, 1_000_000); err != nil {
			return "", 0, err
		}
		iterations, err := runRawSourceKernelLoop(worker, "outer")
		if err != nil {
			return "", iterations, err
		}
		return worker.digest(), iterations, nil
	}
	if exactIterations < 0 || exactIterations > 4096 {
		return "", 0, fmt.Errorf("raw source iteration count is outside 1..4096")
	}
	if exactIterations != 0 {
		for iteration := 0; iteration < exactIterations; iteration++ {
			if _, err := runRawSourceKernelIteration(worker, kernel); err != nil {
				return "", iteration, err
			}
		}
		return worker.digest(), exactIterations, nil
	}
	if !loop {
		_, err := runRawSourceKernelIteration(worker, kernel)
		if err != nil {
			return "", 0, err
		}
		return worker.digest(), 1, nil
	}
	iterations, err := runRawSourceKernelLoop(worker, kernel)
	if err != nil {
		return "", iterations, err
	}
	return worker.digest(), iterations, nil
}

func currentRawSourceReport() (any, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	worker := lastRawSourceState
	registers := make(map[string]string, 32)
	for index, value := range worker.x {
		registers[fmt.Sprintf("x%d", index)] = fmt.Sprintf("%#x", value)
	}
	registers["sp"] = fmt.Sprintf("%#x", worker.sp)
	vectors := make(map[string]string, len(worker.vectors))
	for index, value := range worker.vectors {
		vectors[fmt.Sprintf("v%d", index)] = fmt.Sprintf("%x", value)
	}
	addresses := make([]uint64, 0, len(worker.model.pages))
	for address := range worker.model.pages {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left] < addresses[right] })
	pages := make(map[string]string, len(addresses))
	dirtyPages := make(map[string]string)
	for _, address := range addresses {
		page := worker.model.pages[address]
		if writable := worker.writable[address]; writable != nil {
			page = writable
		}
		pages[fmt.Sprintf("%#x", address)] = fmt.Sprintf("%x", sha256.Sum256(page))
		if worker.dirty[address] {
			dirtyPages[fmt.Sprintf("%#x", address)] = fmt.Sprintf("%x", page)
		}
	}
	accessedPages := make([]string, 0, len(worker.accessed))
	for address := range worker.accessed {
		accessedPages = append(accessedPages, fmt.Sprintf("%#x", address))
	}
	sort.Strings(accessedPages)
	return map[string]any{
		"schema":           "unfairplay-raw-source-state-v1",
		"registers":        registers,
		"vectors":          vectors,
		"flags":            map[string]bool{"n": worker.n, "z": worker.z, "c": worker.c, "v": worker.v},
		"page_sha256":      pages,
		"dirty_page_bytes": dirtyPages,
		"accessed_pages":   accessedPages,
		"state_sha256":     worker.digest(),
	}, nil
}

func currentRawSourceBytes(size int) ([]byte, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	if size != 192 && size != 224 {
		return nil, fmt.Errorf("raw source output size must be 192 or 224 bytes")
	}
	profile, err := executionProfileForModel(lastRawSourceState.model)
	if err != nil {
		return nil, err
	}
	return lastRawSourceState.outputBytes(profile.sourceAddress, size)
}

func currentRawSourceFrameBytes() ([]byte, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	profile, err := executionProfileForModel(lastRawSourceState.model)
	if err != nil {
		return nil, err
	}
	return lastRawSourceState.outputBytes(profile.frameAddress, 16)
}

func currentRawSourceSINFMaterialBytes() ([]byte, error) {
	if lastRawSourceState == nil {
		return nil, fmt.Errorf("raw source state is unavailable")
	}
	profile, err := executionProfileForModel(lastRawSourceState.model)
	if err != nil {
		return nil, err
	}
	if lastRawSourceState.x[29] < profile.sinfFrameOffset {
		return nil, fmt.Errorf("current-SINF frame pointer is invalid")
	}
	return lastRawSourceState.outputBytes(lastRawSourceState.x[29]-profile.sinfFrameOffset, 16)
}

func rawSourceAtom(blob []byte, start, limit int, name string) (int, int, error) {
	for cursor := start; cursor < limit; {
		if limit-cursor < 8 {
			return 0, 0, fmt.Errorf("SINF atom list is truncated")
		}
		size := int(binary.BigEndian.Uint32(blob[cursor : cursor+4]))
		if size < 8 || size > limit-cursor {
			return 0, 0, fmt.Errorf("SINF atom has invalid bounds")
		}
		if string(blob[cursor+4:cursor+8]) == name {
			return cursor + 8, cursor + size, nil
		}
		cursor += size
	}
	return 0, 0, fmt.Errorf("SINF has no %q atom", name)
}

func rawSourceSINFSelector(blob []byte) (uint32, uint32, error) {
	rootStart, rootEnd, err := rawSourceAtom(blob, 0, len(blob), "sinf")
	if err != nil || rootStart != 8 || rootEnd != len(blob) {
		return 0, 0, fmt.Errorf("SINF root is invalid")
	}
	schiStart, schiEnd, err := rawSourceAtom(blob, rootStart, rootEnd, "schi")
	if err != nil {
		return 0, 0, err
	}
	values := [2]uint32{}
	for index, name := range []string{"user", "key "} {
		start, end, atomErr := rawSourceAtom(blob, schiStart, schiEnd, name)
		if atomErr != nil || end-start != 4 {
			return 0, 0, fmt.Errorf("SINF selector atom %q is invalid", name)
		}
		values[index] = binary.BigEndian.Uint32(blob[start:end])
	}
	return values[0], values[1], nil
}

func currentRawSourceEnrollmentPack() ([]byte, error) {
	material, err := currentRawSourceSINFMaterialBytes()
	if err != nil {
		return nil, err
	}
	var sinf []byte
	if activeRawSourceRuntime != nil {
		for suffix, data := range activeRawSourceRuntime.files {
			if strings.HasSuffix(suffix, ".sinf") {
				if sinf != nil {
					return nil, fmt.Errorf("enrollment model requires exactly one installed SINF")
				}
				sinf = data
			}
		}
	}
	if sinf == nil {
		return nil, fmt.Errorf("enrollment model requires one installed SINF mapping")
	}
	user, keyID, err := rawSourceSINFSelector(sinf)
	if err != nil {
		return nil, err
	}
	profile, err := executionProfileForModel(lastRawSourceState.model)
	if err != nil {
		return nil, err
	}
	const modelBytes = 4184
	pack := make([]byte, 0, modelBytes)
	pack = append(pack, []byte("FPSENR2\x00")...)
	var word [4]byte
	binary.LittleEndian.PutUint32(word[:], 2)
	pack = append(pack, word[:]...)
	binary.LittleEndian.PutUint32(word[:], modelBytes)
	pack = append(pack, word[:]...)
	pack = append(pack, profile.binaryHash[:]...)
	binary.LittleEndian.PutUint32(word[:], user)
	pack = append(pack, word[:]...)
	binary.LittleEndian.PutUint32(word[:], keyID)
	pack = append(pack, word[:]...)
	for index, value := range material {
		pack = append(pack, value^profile.currentSINFMask[index])
	}
	pack = append(pack, profile.currentSINFWhite[:]...)
	pack = append(pack, profile.currentSINFInput[:]...)
	if len(pack) != modelBytes {
		return nil, fmt.Errorf("generated enrollment model has invalid size %d", len(pack))
	}
	return pack, nil
}

func runRawSourceKernelIteration(worker *state, kernel string) (bool, error) {
	profile, profileErr := executionProfileForModel(worker.model)
	if profileErr != nil {
		return false, profileErr
	}
	var exit bool
	var err error
	switch kernel {
	case "account-cfg":
		_, _, err = runRawSourceAccountEntryCFG(worker, activeRawSourceRuntime, 1_000_000)
		exit = true
	case "bootstrap":
		err = profile.runBootstrap(worker, fault{})
		exit = worker.x[3] != profile.bootstrapStart
	case "bootstrap-cfg":
		_, _, err = runRawSourceBootstrapCFG(worker, activeRawSourceRuntime, 1_000_000)
		exit = true
	case "writer":
		exit = uint32(worker.x[1])+0x9FCE627E > 0xC7
		err = profile.runWriter(worker, fault{})
	case "tail":
		exit = uint32(worker.x[3])+0x9FCE627E >= 0x12C
		err = profile.runTail(worker, fault{})
	case "even":
		exit = uint32(worker.x[12])+2 > 0x63
		err = profile.runEven(worker, fault{})
	case "odd":
		exit = uint32(worker.x[1])+0x9FCE627F > 0x64
		err = profile.runOdd(worker, fault{})
	case "digest":
		err = profile.runDigest(worker, fault{})
	case "outer":
		err = profile.runOuter(worker, fault{})
		if err == nil && worker.x[12] == profile.outerCycle {
			err = runRawSourceCycleBoundary(worker, fault{})
			if err == nil {
				exit, err = rawSourceCycleExited(worker)
			}
		} else {
			exit = worker.x[12] != profile.outerStart
		}
	case "cycle":
		err = runRawSourceCycleBoundary(worker, fault{})
		if err == nil {
			exit, err = rawSourceCycleExited(worker)
		}
	case "outer-primary":
		err = profile.runOuter(worker, fault{})
		exit = worker.x[12] != profile.outerStart
	default:
		return false, fmt.Errorf("unknown raw source kernel %q", kernel)
	}
	if err != nil {
		return false, err
	}
	if kernel == "digest" {
		exit = worker.z
		if !exit {
			err = profile.runDigestPrologue(worker, fault{})
		}
	}
	return exit, err
}

func rawSourceCycleExited(worker *state) (bool, error) {
	profile, err := executionProfileForModel(worker.model)
	if err != nil {
		return false, err
	}
	if worker.x[9] == profile.outerStart {
		return false, nil
	}
	return worker.x[8] != profile.outerStart, nil
}

func runRawSourceKernelLoop(worker *state, kernel string) (int, error) {
	if kernel == "digest-natural" {
		profile, err := executionProfileForModel(worker.model)
		if err != nil {
			return 0, err
		}
		if err := profile.runDigestPrologue(worker, fault{}); err != nil {
			return 0, err
		}
		kernel = "digest"
	}
	limit := 1024
	if kernel == "bootstrap" {
		limit = 200000
	}
	for iterations := 1; iterations <= limit; iterations++ {
		exit, err := runRawSourceKernelIteration(worker, kernel)
		if err != nil {
			return iterations - 1, err
		}
		if exit {
			return iterations, nil
		}
	}
	return limit, fmt.Errorf("raw source writer loop did not reach its bounded exit")
}
