package recovery

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sort"
)

const (
	modelMagic   = "FPGOOR1\x00"
	modelVersion = uint32(2)
	pageSize     = uint64(0x1000)
)

type model struct {
	allowDestinationPages bool
	exactExtractedBlocks  map[uint64]compactBlock
	selectionMaxBlocks    int
	profile               *executionProfile
	binaryHash            [32]byte
	block                 uint64
	registers             [31]uint64
	sp                    uint64
	n, z, c, v            bool
	pages                 map[uint64][]byte
	domains               map[domainKey][256]uint64
}

func (m *model) patch(address uint64, value []byte) error {
	for len(value) != 0 {
		base := address &^ (pageSize - 1)
		page := m.pages[base]
		if page == nil {
			return fmt.Errorf("oracle patch address %#x is outside the model", address)
		}
		// Models loaded from embedded assets are process-global byte slices from
		// the caller's point of view. Clone every touched page before applying a
		// private runtime input so the packaged asset remains immutable.
		page = append([]byte(nil), page...)
		m.pages[base] = page
		offset := address & (pageSize - 1)
		count := min(len(value), int(pageSize-offset))
		copy(page[offset:offset+uint64(count)], value[:count])
		address += uint64(count)
		value = value[count:]
	}
	return nil
}

type domainKey struct {
	pc       uint64
	register uint8
}

func loadModel(path string) (*model, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Go FairPlay oracle model is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("Go FairPlay oracle model must be mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return loadModelReader(file)
}

func loadModelBytes(data []byte) (*model, error) {
	return loadModelReader(bytes.NewReader(data))
}

func loadModelReader(input io.Reader) (*model, error) {
	stream, err := gzip.NewReader(input)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	read := func(value any) error { return binary.Read(stream, binary.LittleEndian, value) }
	var magic [8]byte
	if _, err := io.ReadFull(stream, magic[:]); err != nil {
		return nil, err
	}
	if string(magic[:]) != modelMagic {
		return nil, fmt.Errorf("invalid Go FairPlay oracle model magic")
	}
	var version uint32
	if err := read(&version); err != nil || version != modelVersion {
		return nil, fmt.Errorf("unsupported Go FairPlay oracle model version")
	}
	result := &model{pages: make(map[uint64][]byte), domains: make(map[domainKey][256]uint64)}
	if _, err := io.ReadFull(stream, result.binaryHash[:]); err != nil {
		return nil, err
	}
	if err := read(&result.block); err != nil {
		return nil, err
	}
	for index := range result.registers {
		if err := read(&result.registers[index]); err != nil {
			return nil, err
		}
	}
	if err := read(&result.sp); err != nil {
		return nil, err
	}
	var flags [4]byte
	if _, err := io.ReadFull(stream, flags[:]); err != nil {
		return nil, err
	}
	result.n, result.z, result.c, result.v = flags[0] != 0, flags[1] != 0, flags[2] != 0, flags[3] != 0
	var pageCount uint32
	if err := read(&pageCount); err != nil || pageCount == 0 || pageCount > 8192 {
		return nil, fmt.Errorf("invalid Go FairPlay oracle page count")
	}
	for range pageCount {
		var address uint64
		if err := read(&address); err != nil || address%pageSize != 0 {
			return nil, fmt.Errorf("invalid Go FairPlay oracle page address")
		}
		if _, exists := result.pages[address]; exists {
			return nil, fmt.Errorf("duplicate Go FairPlay oracle page %#x", address)
		}
		page := make([]byte, pageSize)
		if _, err := io.ReadFull(stream, page); err != nil {
			return nil, err
		}
		result.pages[address] = page
	}
	var domainCount uint32
	if err := read(&domainCount); err != nil || domainCount > 64 {
		return nil, fmt.Errorf("invalid Go FairPlay oracle domain count")
	}
	for range domainCount {
		var key domainKey
		if err := read(&key.pc); err != nil {
			return nil, err
		}
		var registerBytes [1]byte
		if _, err := io.ReadFull(stream, registerBytes[:]); err != nil || registerBytes[0] >= 31 {
			return nil, fmt.Errorf("invalid Go FairPlay oracle domain register")
		}
		key.register = registerBytes[0]
		var reserved [7]byte
		if _, err := io.ReadFull(stream, reserved[:]); err != nil || reserved != [7]byte{} {
			return nil, fmt.Errorf("invalid Go FairPlay oracle domain envelope")
		}
		if _, exists := result.domains[key]; exists {
			return nil, fmt.Errorf("duplicate Go FairPlay oracle domain")
		}
		var values [256]uint64
		for index := range values {
			if err := read(&values[index]); err != nil {
				return nil, err
			}
			if index != 0 && values[index] <= values[index-1] {
				return nil, fmt.Errorf("Go FairPlay oracle domain is not ordered")
			}
		}
		result.domains[key] = values
	}
	var trailing [1]byte
	if count, err := stream.Read(trailing[:]); err != io.EOF || count != 0 {
		return nil, fmt.Errorf("Go FairPlay oracle model has trailing data")
	}
	return result, nil
}

type state struct {
	model              *model
	x                  [31]uint64
	vectors            [32][16]byte
	sp                 uint64
	n, z               bool
	c, v               bool
	writable           map[uint64][]byte
	touched            []uint64
	dirty              map[uint64]bool
	accessed           map[uint64]bool
	initialized        map[uint64][]bool
	mapped             map[uint64][]byte
	destinationPages   map[uint64]bool
	extractedBlockHits int
}

func newState(value *model) *state {
	return &state{
		model: value, writable: make(map[uint64][]byte),
		dirty: make(map[uint64]bool), accessed: make(map[uint64]bool), initialized: make(map[uint64][]bool),
		mapped: make(map[uint64][]byte), destinationPages: capturedDestinationPages(value),
	}
}

// capturedDestinationPages identifies snapshot holes that are bounded by the
// original captured heap. A page can only be read after every requested byte
// has first been written by the evaluated program.
func capturedDestinationPages(value *model) map[uint64]bool {
	result := make(map[uint64]bool)
	if !value.allowDestinationPages {
		return result
	}
	const low = uint64(0x710000000000)
	const high = uint64(0x710000100000)
	var anchors []uint64
	for address := range value.pages {
		if address >= low && address < high {
			anchors = append(anchors, address)
		}
	}
	sort.Slice(anchors, func(left, right int) bool { return anchors[left] < anchors[right] })
	for index, address := range anchors {
		if address >= low+pageSize && value.pages[address-pageSize] == nil {
			result[address-pageSize] = true
		}
		if index > 0 && address-anchors[index-1] <= 33*pageSize {
			for page := anchors[index-1] + pageSize; page < address; page += pageSize {
				result[page] = true
			}
		}
	}
	return result
}

func (s *state) reset() {
	for _, address := range s.touched {
		copy(s.writable[address], s.model.pages[address])
		delete(s.dirty, address)
	}
	for address, page := range s.mapped {
		clear(page)
		clear(s.writable[address])
		delete(s.writable, address)
	}
	clear(s.mapped)
	clear(s.initialized)
	s.touched = s.touched[:0]
	clear(s.accessed)
	s.x = s.model.registers
	s.vectors = [32][16]byte{}
	s.sp = s.model.sp
	s.n, s.z, s.c, s.v = s.model.n, s.model.z, s.model.c, s.model.v

}

func (s *state) vectorLane(register, lane, bits int) uint64 {
	offset := lane * bits / 8
	switch bits {
	case 8:
		return uint64(s.vectors[register][offset])
	case 16:
		return uint64(binary.LittleEndian.Uint16(s.vectors[register][offset:]))
	case 32:
		return uint64(binary.LittleEndian.Uint32(s.vectors[register][offset:]))
	case 64:
		return binary.LittleEndian.Uint64(s.vectors[register][offset:])
	default:
		panic("unsupported vector lane width")
	}
}

func (s *state) setVectorLane(register, lane, bits int, value uint64) {
	offset := lane * bits / 8
	switch bits {
	case 8:
		s.vectors[register][offset] = byte(value)
	case 16:
		binary.LittleEndian.PutUint16(s.vectors[register][offset:], uint16(value))
	case 32:
		binary.LittleEndian.PutUint32(s.vectors[register][offset:], uint32(value))
	case 64:
		binary.LittleEndian.PutUint64(s.vectors[register][offset:], value)
	default:
		panic("unsupported vector lane width")
	}
}

func (s *state) clearVector(register int) { s.vectors[register] = [16]byte{} }

func (s *state) loadVector(register int, address uint64, size int) error {
	data, err := s.outputBytes(address, size)
	if err != nil {
		return err
	}
	s.clearVector(register)
	copy(s.vectors[register][:], data)
	return nil
}

func (s *state) storeVector(register int, address uint64, size int) error {
	return s.store(address, s.vectors[register][:size])
}

func (s *state) vectorDup(register, lanes, bits int, value uint64) {
	s.clearVector(register)
	for lane := range lanes {
		s.setVectorLane(register, lane, bits, value)
	}
}

func (s *state) vectorBinary(operation string, destination, left, right, lanes, bits int) {
	var result [16]byte
	for lane := range lanes {
		leftValue := s.vectorLane(left, lane, bits)
		rightValue := s.vectorLane(right, lane, bits)
		var value uint64
		switch operation {
		case "add":
			value = leftValue + rightValue
		case "sub":
			value = leftValue - rightValue
		case "mul":
			value = leftValue * rightValue
		case "eor":
			value = leftValue ^ rightValue
		default:
			panic("unsupported vector binary operation")
		}
		offset := lane * bits / 8
		switch bits {
		case 8:
			result[offset] = byte(value)
		case 16:
			binary.LittleEndian.PutUint16(result[offset:], uint16(value))
		case 32:
			binary.LittleEndian.PutUint32(result[offset:], uint32(value))
		case 64:
			binary.LittleEndian.PutUint64(result[offset:], value)
		}
	}
	s.vectors[destination] = result
}

func (s *state) vectorMultiplyAccumulate(destination, left, right, lanes, bits int, subtract bool) {
	previous := s.vectors[destination]
	for lane := range lanes {
		offset := lane * bits / 8
		var accumulator uint64
		switch bits {
		case 8:
			accumulator = uint64(previous[offset])
		case 16:
			accumulator = uint64(binary.LittleEndian.Uint16(previous[offset:]))
		case 32:
			accumulator = uint64(binary.LittleEndian.Uint32(previous[offset:]))
		case 64:
			accumulator = binary.LittleEndian.Uint64(previous[offset:])
		}
		product := s.vectorLane(left, lane, bits) * s.vectorLane(right, lane, bits)
		if subtract {
			s.setVectorLane(destination, lane, bits, accumulator-product)
		} else {
			s.setVectorLane(destination, lane, bits, accumulator+product)
		}
	}
}

func (s *state) vectorUnsignedMultiplyLong(destination, left, right, lanes, inputBits int, high bool) {
	start := 0
	if high {
		start = lanes
	}
	leftValues := make([]uint64, lanes)
	rightValues := make([]uint64, lanes)
	for lane := range lanes {
		leftValues[lane] = s.vectorLane(left, start+lane, inputBits)
		rightValues[lane] = s.vectorLane(right, start+lane, inputBits)
	}
	s.clearVector(destination)
	for lane := range lanes {
		value := leftValues[lane] * rightValues[lane]
		s.setVectorLane(destination, lane, inputBits*2, value)
	}
}

func (s *state) vectorUnsignedShiftLong(destination, source, lanes, inputBits, amount int, high bool) {
	start := 0
	if high {
		start = lanes
	}
	values := make([]uint64, lanes)
	for lane := range lanes {
		values[lane] = s.vectorLane(source, start+lane, inputBits)
	}
	s.clearVector(destination)
	for lane := range lanes {
		s.setVectorLane(destination, lane, inputBits*2, values[lane]<<amount)
	}
}

func (s *state) vectorShiftRightNarrow(destination, source, lanes, outputBits, amount int) {
	values := make([]uint64, lanes)
	for lane := range lanes {
		values[lane] = s.vectorLane(source, lane, outputBits*2)
	}
	s.clearVector(destination)
	for lane := range lanes {
		s.setVectorLane(destination, lane, outputBits, values[lane]>>amount)
	}
}

func (s *state) vectorUnsignedShiftRight(destination, source, lanes, bits, amount int) {
	values := make([]uint64, lanes)
	for lane := range lanes {
		values[lane] = s.vectorLane(source, lane, bits)
	}
	s.clearVector(destination)
	for lane := range lanes {
		s.setVectorLane(destination, lane, bits, values[lane]>>amount)
	}
}

func (s *state) vectorUnsignedShift(destination, source, shifts, lanes, bits int) {
	values := make([]uint64, lanes)
	shiftValues := make([]uint64, lanes)
	for lane := range lanes {
		values[lane] = s.vectorLane(source, lane, bits)
		shiftValues[lane] = s.vectorLane(shifts, lane, bits)
	}
	s.clearVector(destination)
	for lane := range lanes {
		value := values[lane]
		shift := int64(signExtendBits(shiftValues[lane], bits, 64))
		if shift >= int64(bits) || shift <= -int64(bits) {
			value = 0
		} else if shift >= 0 {
			value <<= uint(shift)
		} else {
			value >>= uint(-shift)
		}
		s.setVectorLane(destination, lane, bits, value)
	}
}

func (s *state) vectorExtractNarrow(destination, source, lanes, outputBits int) {
	values := make([]uint64, lanes)
	for lane := range lanes {
		values[lane] = s.vectorLane(source, lane, outputBits*2)
	}
	s.clearVector(destination)
	for lane := range lanes {
		s.setVectorLane(destination, lane, outputBits, values[lane])
	}
}

func (s *state) vectorUnzipEven(destination, left, right, lanes, bits int) {
	half := lanes / 2
	leftValues := make([]uint64, half)
	rightValues := make([]uint64, half)
	for lane := range half {
		leftValues[lane] = s.vectorLane(left, lane*2, bits)
		rightValues[lane] = s.vectorLane(right, lane*2, bits)
	}
	s.clearVector(destination)
	for lane := range half {
		s.setVectorLane(destination, lane, bits, leftValues[lane])
		s.setVectorLane(destination, half+lane, bits, rightValues[lane])
	}
}

func (s *state) vectorEor3(destination, first, second, third int) {
	for index := range 16 {
		s.vectors[destination][index] = s.vectors[first][index] ^ s.vectors[second][index] ^ s.vectors[third][index]
	}
}

func (s *state) vectorTable(destination int, tables []int, indexes int) {
	var result [16]byte
	for lane, index := range s.vectors[indexes] {
		if int(index) < len(tables)*16 {
			result[lane] = s.vectors[tables[int(index)/16]][int(index)%16]
		}
	}
	s.vectors[destination] = result
}

func (s *state) begin(block [16]byte) error {
	return s.beginBytes(block[:])
}

func (s *state) beginBytes(input []byte) error {
	s.reset()
	return s.store(s.model.block, input)
}

func (s *state) digest() string {
	hash := sha256.New()
	var word [8]byte
	for _, value := range s.x {
		binary.LittleEndian.PutUint64(word[:], value)
		_, _ = hash.Write(word[:])
	}
	binary.LittleEndian.PutUint64(word[:], s.sp)
	_, _ = hash.Write(word[:])
	flags := []byte{0, 0, 0, 0}
	for index, value := range []bool{s.n, s.z, s.c, s.v} {
		if value {
			flags[index] = 1
		}
	}
	_, _ = hash.Write(flags)
	addresses := make([]uint64, 0, len(s.model.pages)+len(s.mapped))
	for address := range s.model.pages {
		addresses = append(addresses, address)
	}
	for address := range s.mapped {
		if s.model.pages[address] == nil {
			addresses = append(addresses, address)
		}
	}
	sort.Slice(addresses, func(left, right int) bool { return addresses[left] < addresses[right] })
	for _, address := range addresses {
		binary.LittleEndian.PutUint64(word[:], address)
		_, _ = hash.Write(word[:])
		page := s.model.pages[address]
		if page == nil {
			page = s.mapped[address]
		}
		if writable := s.writable[address]; writable != nil {
			page = writable
		}
		_, _ = hash.Write(page)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (s *state) page(address uint64, write bool) ([]byte, error) {
	base := address &^ (pageSize - 1)
	s.accessed[base] = true
	page := s.model.pages[base]
	if page == nil {
		page = s.mapped[base]
	}
	if page == nil && write && s.destinationPages[base] && len(s.initialized) < 32 {
		page = make([]byte, pageSize)
		s.mapped[base] = page
		s.initialized[base] = make([]bool, pageSize)
	}
	if page == nil {
		return nil, fmt.Errorf("oracle memory address %#x is outside the model", address)
	}
	if !write {
		if writable := s.writable[base]; writable != nil {
			return writable, nil
		}
		return page, nil
	}
	writable := s.writable[base]
	if writable == nil {
		writable = append([]byte(nil), page...)
		s.writable[base] = writable
	}
	if !s.dirty[base] {
		s.dirty[base] = true
		s.touched = append(s.touched, base)
	}
	return writable, nil
}

func (s *state) load(address uint64, size int) (uint64, error) {
	if size != 1 && size != 2 && size != 4 && size != 8 {
		return 0, fmt.Errorf("unsupported oracle load size %d", size)
	}
	if address&(pageSize-1)+uint64(size) <= pageSize {
		page, err := s.page(address, false)
		if err != nil {
			return 0, err
		}
		offset := address & (pageSize - 1)
		if known := s.initialized[address&^(pageSize-1)]; known != nil {
			for index := offset; index < offset+uint64(size); index++ {
				if !known[index] {
					return 0, fmt.Errorf("read of uncaptured, unwritten memory %#x", address)
				}
			}
		}
		switch size {
		case 1:
			return uint64(page[offset]), nil
		case 2:
			return uint64(binary.LittleEndian.Uint16(page[offset : offset+2])), nil
		case 4:
			return uint64(binary.LittleEndian.Uint32(page[offset : offset+4])), nil
		default:
			return binary.LittleEndian.Uint64(page[offset : offset+8]), nil
		}
	}
	var buffer [8]byte
	for index := 0; index < size; index++ {
		value, err := s.load(address+uint64(index), 1)
		if err != nil {
			return 0, err
		}
		buffer[index] = byte(value)
	}
	return binary.LittleEndian.Uint64(buffer[:]), nil
}

func (s *state) store(address uint64, value []byte) error {
	for len(value) != 0 {
		page, err := s.page(address, true)
		if err != nil {
			return err
		}
		offset := address & (pageSize - 1)
		count := min(len(value), int(pageSize-offset))
		copy(page[offset:offset+uint64(count)], value[:count])
		if known := s.initialized[address&^(pageSize-1)]; known != nil {
			for index := offset; index < offset+uint64(count); index++ {
				known[index] = true
			}
		}
		address += uint64(count)
		value = value[count:]
	}
	return nil
}

func (s *state) mapZero(address, size uint64) error {
	if size == 0 || address&(pageSize-1) != 0 {
		return fmt.Errorf("invalid zero mapping %#x+%#x", address, size)
	}
	end := address + size
	if end < address {
		return fmt.Errorf("zero mapping overflows")
	}
	for page := address; page < end; page += pageSize {
		if s.model.pages[page] == nil && s.mapped[page] == nil {
			s.mapped[page] = make([]byte, pageSize)
		}
	}
	return nil
}

func (s *state) readCString(address uint64, limit int) (string, error) {
	if limit <= 0 {
		return "", fmt.Errorf("invalid C-string limit")
	}
	value := make([]byte, 0, min(limit, 256))
	for len(value) < limit {
		octet, err := s.load(address+uint64(len(value)), 1)
		if err != nil {
			return "", err
		}
		if octet == 0 {
			return string(value), nil
		}
		value = append(value, byte(octet))
	}
	return "", fmt.Errorf("unterminated C string at %#x", address)
}

func (s *state) storeValue(address, value uint64, size int) error {
	var buffer [8]byte
	switch size {
	case 1:
		buffer[0] = byte(value)
	case 2:
		binary.LittleEndian.PutUint16(buffer[:2], uint16(value))
	case 4:
		binary.LittleEndian.PutUint32(buffer[:4], uint32(value))
	case 8:
		binary.LittleEndian.PutUint64(buffer[:], value)
	default:
		return fmt.Errorf("unsupported oracle store size %d", size)
	}
	return s.store(address, buffer[:size])
}

func (s *state) output() ([16]byte, error) {
	var result [16]byte
	for index := range result {
		value, err := s.load(s.model.block+uint64(index), 1)
		if err != nil {
			return result, err
		}
		result[index] = byte(value)
	}
	return result, nil
}

func (s *state) outputBytes(address uint64, size int) ([]byte, error) {
	result := make([]byte, size)
	for index := range result {
		value, err := s.load(address+uint64(index), 1)
		if err != nil {
			return nil, err
		}
		result[index] = byte(value)
	}
	return result, nil
}

type faultKind uint8

const (
	faultNone faultKind = iota
	faultIndex
	faultPointer
)

type fault struct {
	pc         uint64
	register   uint8
	shift      uint8
	value      uint8
	kind       faultKind
	restore    bool
	tableBytes uint16
	entryBytes uint8
}

func (s *state) beforeFault(selected fault, pc uint64) (uint64, bool, error) {
	if selected.kind == faultNone || selected.pc != pc {
		return 0, false, nil
	}
	if selected.register >= 31 {
		return 0, false, fmt.Errorf("invalid oracle fault register")
	}
	old := s.x[selected.register]
	switch selected.kind {
	case faultIndex:
		if values, ok := s.model.domains[domainKey{pc: selected.pc, register: selected.register}]; ok {
			needle := uint64(uint32(old))
			low, high := 0, len(values)
			for low < high {
				middle := int(uint(low+high) >> 1)
				if values[middle] < needle {
					low = middle + 1
				} else {
					high = middle
				}
			}
			if low == len(values) || values[low] != needle {
				return 0, false, fmt.Errorf("index value %#x is outside the learned domain", needle)
			}
			s.x[selected.register] = values[low^int(selected.value)]
		} else {
			s.x[selected.register] = uint64(uint32(old) ^ uint32(selected.value)<<selected.shift)
		}
	case faultPointer:
		if selected.tableBytes == 0 || selected.entryBytes == 0 || selected.tableBytes&(selected.tableBytes-1) != 0 {
			return 0, false, fmt.Errorf("invalid pointer-fault geometry")
		}
		mask := uint64(selected.tableBytes - 1)
		base := old &^ mask
		offset := old - base
		if offset >= uint64(selected.tableBytes) || offset%uint64(selected.entryBytes) != 0 {
			return 0, false, fmt.Errorf("pointer fault %#x is outside its table", old)
		}
		position := offset / uint64(selected.entryBytes)
		s.x[selected.register] = base + (position^uint64(selected.value))*uint64(selected.entryBytes)
	default:
		return 0, false, fmt.Errorf("unsupported fault kind")
	}
	return old, selected.restore, nil
}

func (s *state) afterFault(selected fault, pc, old uint64, restore bool) {
	if restore && selected.pc == pc {
		s.x[selected.register] = old
	}
}

func (s *state) compare32(left, right uint32) {
	result := left - right
	s.n = result&0x80000000 != 0
	s.z = result == 0
	s.c = left >= right
	s.v = ((left ^ right) & (left ^ result) & 0x80000000) != 0
}

func (s *state) compare64(left, right uint64) {
	result := left - right
	s.n = result&0x8000000000000000 != 0
	s.z = result == 0
	s.c = left >= right
	s.v = ((left ^ right) & (left ^ result) & 0x8000000000000000) != 0
}

func (s *state) subtractWithFlags(left, right uint64, width int) uint64 {
	if width == 32 {
		s.compare32(uint32(left), uint32(right))
		return uint64(uint32(left) - uint32(right))
	}
	s.compare64(left, right)
	return left - right
}

func (s *state) addWithCarry(left, right uint64, carry bool, width int) uint64 {
	carryValue := uint64(0)
	if carry {
		carryValue = 1
	}
	if width == 32 {
		result64 := uint64(uint32(left)) + uint64(uint32(right)) + carryValue
		result := uint32(result64)
		s.n = result&0x80000000 != 0
		s.z = result == 0
		s.c = result64>>32 != 0
		s.v = (^(uint32(left) ^ uint32(right)) & (uint32(left) ^ result) & 0x80000000) != 0
		return uint64(result)
	}
	result, carryOut := bits.Add64(left, right, carryValue)
	s.n = result&0x8000000000000000 != 0
	s.z = result == 0
	s.c = carryOut != 0
	s.v = (^(left ^ right) & (left ^ result) & 0x8000000000000000) != 0
	return result
}

func multiplyHigh64(left, right uint64) uint64 {
	high, _ := bits.Mul64(left, right)
	return high
}

func signExtendBits(value uint64, bits, width int) uint64 {
	if bits <= 0 || bits > width {
		panic("invalid generated sign-extension width")
	}
	mask := bitMask(bits, width)
	value &= mask
	sign := uint64(1) << (bits - 1)
	if value&sign != 0 {
		value |= ^mask
	}
	if width == 32 {
		return uint64(uint32(value))
	}
	return value
}

func unsignedDivide(left, right uint64, width int) uint64 {
	if width == 32 {
		divisor := uint32(right)
		if divisor == 0 {
			return 0
		}
		return uint64(uint32(left) / divisor)
	}
	if right == 0 {
		return 0
	}
	return left / right
}

func countLeadingZeros(value uint64, width int) uint64 {
	if width == 32 {
		return uint64(bits.LeadingZeros32(uint32(value)))
	}
	return uint64(bits.LeadingZeros64(value))
}

func reverseBytes32(value uint64) uint64 { return uint64(bits.ReverseBytes32(uint32(value))) }

func reverseBytes64(value uint64) uint64 { return bits.ReverseBytes64(value) }

func (s *state) test32(value uint32) {
	s.n, s.z, s.c, s.v = value&0x80000000 != 0, value == 0, false, false
}

func (s *state) test64(value uint64) {
	s.n, s.z, s.c, s.v = value&0x8000000000000000 != 0, value == 0, false, false
}

func (s *state) setNZCV(value int) {
	s.n = value&8 != 0
	s.z = value&4 != 0
	s.c = value&2 != 0
	s.v = value&1 != 0
}

func (s *state) condition(name string) bool {
	switch name {
	case "eq":
		return s.z
	case "ne":
		return !s.z
	case "hs":
		return s.c
	case "lo":
		return !s.c
	case "hi":
		return s.c && !s.z
	case "ls":
		return !s.c || s.z
	case "lt":
		return s.n != s.v
	case "le":
		return s.z || s.n != s.v
	case "gt":
		return !s.z && s.n == s.v
	case "ge":
		return s.n == s.v
	case "mi":
		return s.n
	case "pl":
		return !s.n
	case "vs":
		return s.v
	case "vc":
		return !s.v
	default:
		panic("unsupported generated condition: " + name)
	}
}

func rotateRight32(value uint32, amount uint32) uint32 {
	amount &= 31
	if amount == 0 {
		return value
	}
	return value>>amount | value<<(32-amount)
}

func mask32(width uint32) uint32 {
	if width >= 32 {
		return ^uint32(0)
	}
	return uint32(1)<<width - 1
}

func signExtend32(value uint32) uint64 { return uint64(int64(int32(value))) }
