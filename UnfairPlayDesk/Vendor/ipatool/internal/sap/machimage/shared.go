package machimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"sync"
)

// OpenShared borrows immutable image bytes and copies only pages changed by
// relocation. Instruction patches are applied while loading into guest memory.
// Input must remain unchanged while the Image is used.
func OpenShared(name string, input []byte) (*Image, error) {
	data, err := ARM64Slice(input)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}

	return openImage(name, data, make(map[uint64][]byte))
}

// OpenSharedVerified opens an immutable image whose SHA-256 digest has already
// been verified by the caller. Universal binaries still hash the selected slice.
func OpenSharedVerified(name string, input []byte, digest [sha256.Size]byte) (*Image, error) {
	data, err := ARM64Slice(input)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}

	if len(data) != len(input) {
		digest = sha256.Sum256(data)
	}

	return openImageWithDigest(name, data, make(map[uint64][]byte), digest, true)
}

func (i *Image) writeAt(offset uint64, data []byte) {
	if i.modified == nil {
		copy(i.data[offset:], data)

		return
	}

	for len(data) > 0 {
		page := offset &^ (pageSize - 1)
		buffer := i.modified[page]

		if buffer == nil {
			buffer = bytes.Clone(i.data[page:min(page+pageSize, uint64(len(i.data)))])
			i.overlay(buffer, page)
			i.modified[page] = buffer
		}

		count := copy(buffer[offset-page:], data)
		offset += uint64(count)
		data = data[count:]
	}
}

func (i *Image) pointerAt(offset uint64) uint64 {
	pageStart := offset &^ (pageSize - 1)
	if offset+pointerSize <= pageStart+pageSize {
		if page := i.modified[pageStart]; page != nil {
			return binary.LittleEndian.Uint64(page[offset-pageStart:])
		}

		if len(i.instructions[pageStart]) == 0 {
			return binary.LittleEndian.Uint64(i.data[offset:])
		}
	}

	var value [8]byte

	copy(value[:], i.data[offset:offset+8])
	i.overlay(value[:], offset)

	return binary.LittleEndian.Uint64(value[:])
}

func (i *Image) writeInstruction(offset uint64, value uint32) {
	if i.modified != nil {
		if i.instructions == nil {
			i.instructions = make(map[uint64][]instructionPatch)
		}

		for page := offset &^ (pageSize - 1); page < offset+4; page += pageSize {
			i.instructions[page] = append(i.instructions[page], instructionPatch{offset, value})
		}

		return
	}

	var data [4]byte

	binary.LittleEndian.PutUint32(data[:], value)
	i.writeAt(offset, data[:])
}

// Overlay private relocations and immutable instruction patches. Clip each page
// and patch to the destination, including unaligned segment and chunk boundaries.
func (i *Image) overlay(data []byte, offset uint64) {
	end := offset + uint64(len(data))
	for page := offset &^ (pageSize - 1); page < end; page += pageSize {
		first, last := max(page, offset), min(page+pageSize, end)
		if modified := i.modified[page]; modified != nil {
			copy(data[first-offset:last-offset], modified[first-page:last-page])

			continue
		}

		for _, patch := range i.instructions[page] {
			start, stop := max(first, patch.offset), min(last, patch.offset+4)
			if start >= stop {
				continue
			}

			var encoded [4]byte

			binary.LittleEndian.PutUint32(encoded[:], patch.value)
			copy(data[start-offset:stop-offset], encoded[start-patch.offset:stop-patch.offset])
		}
	}
}

// Keep staging memory bounded regardless of image size and guest count.
func (i *Image) writeSegment(memory Memory, address, start, end uint64, buffer []byte) error {
	if len(i.modified) == 0 && len(i.instructions) == 0 {
		if err := memory.MemWrite(address, i.data[start:end]); err != nil {
			return fmt.Errorf("write image data: %w", err)
		}

		return nil
	}

	for position := start; position < end; {
		stop := min(position+uint64(len(buffer)), end)
		data := i.data[position:stop]
		for page := position &^ (pageSize - 1); page < stop; page += pageSize {
			if i.modified[page] != nil || len(i.instructions[page]) != 0 {
				data = buffer[:stop-position]
				copy(data, i.data[position:stop])
				i.overlay(data, position)
				break
			}
		}

		if err := memory.MemWrite(address+position-start, data); err != nil {
			return fmt.Errorf("write image chunk: %w", err)
		}

		position = stop
	}

	return nil
}

// Mach-O fixup parsing must observe the same rewritten bytes that will be loaded
// into the guest, including instruction patches in mixed code/data sections.
type imageInput struct{ image *Image }

func (r imageInput) ReadAt(data []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("invalid image offset %d", offset)
	}

	if offset >= int64(len(r.image.data)) {
		return 0, io.EOF
	}

	count := copy(data, r.image.data[offset:])
	if len(r.image.instructions) > 0 || len(r.image.modified) > 0 {
		r.image.overlay(data[:count], uint64(offset))
	}

	if count < len(data) {
		return count, io.EOF
	}

	return count, nil
}

// Cache only pointer locations. The resolved guest addresses and resulting
// relocations stay private to each VM because shims can use different addresses.
type prelinkedFixup struct {
	offset, original uint64
}

var sharedPrelink struct {
	sync.Mutex
	digest  [sha256.Size]byte
	symbols map[uint64]string
	fixups  []prelinkedFixup
}

func (i *Image) prelinkedFixups(external map[uint64]string) []prelinkedFixup {
	if i.modified == nil || len(i.modified) != 0 {
		return i.scanPrelinkedFixups(external)
	}

	sharedPrelink.Lock()
	defer sharedPrelink.Unlock()
	if sharedPrelink.digest != i.sharedDigest || !maps.Equal(sharedPrelink.symbols, external) {
		sharedPrelink.fixups = i.scanPrelinkedFixups(external)
		sharedPrelink.digest = i.sharedDigest
		sharedPrelink.symbols = maps.Clone(external)
	}
	return sharedPrelink.fixups
}

func (i *Image) scanPrelinkedFixups(external map[uint64]string) []prelinkedFixup {
	var fixups []prelinkedFixup
	for _, item := range i.segments {
		if item.name == "__TEXT" || item.name == "__LINKEDIT" || item.fileSize < pointerSize {
			continue
		}
		start := item.fileOff
		if remainder := item.address % pointerSize; remainder != 0 {
			start += pointerSize - remainder
		}
		end := item.fileOff + item.fileSize
		for offset := start; offset <= end-pointerSize; offset += pointerSize {
			current := i.pointerAt(offset)
			if _, ok := external[current]; ok {
				fixups = append(fixups, prelinkedFixup{offset: offset, original: current})
			}
		}
	}
	return fixups
}
