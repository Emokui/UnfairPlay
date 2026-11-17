package fairplay

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sort"
	"strings"
)

// IPAHasEncryptedImages inspects Mach-O encryption markers without loading a
// model, applying patches, or reading any license material.
func IPAHasEncryptedImages(path string) (bool, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return false, err
	}
	defer archive.Close()

	found := false
	var incomplete error
	for _, file := range archive.File {
		if !strings.HasPrefix(file.Name, "Payload/") || !file.Mode().IsRegular() || file.UncompressedSize64 < 4 {
			continue
		}
		image, encrypted, err := inspectIPAImage(file)
		if err != nil {
			incomplete = err
			continue
		}
		if encrypted {
			return true, nil
		}
		found = found || image
	}
	if incomplete != nil {
		return false, incomplete
	}
	if !found {
		return false, errors.New("no Mach-O executable found in IPA")
	}
	return false, nil
}

func inspectIPAImage(file *zip.File) (found, encrypted bool, err error) {
	var reader io.Reader
	if file.Method == zip.Store {
		reader, err = file.OpenRaw()
	} else {
		var stream io.ReadCloser
		stream, err = file.Open()
		if err == nil {
			defer stream.Close()
			reader = stream
		}
	}
	if err != nil {
		return false, false, err
	}
	var magic [4]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return false, false, err
	}
	if isFatMachO(magic[:]) {
		encrypted, err := inspectIPAFatImage(reader, magic[:], file.UncompressedSize64)
		return true, encrypted, err
	}
	if isKnownUnsupportedMachO(magic[:]) {
		return false, false, errors.New("unsupported Mach-O format")
	}
	switch binary.LittleEndian.Uint32(magic[:]) {
	case mhMagic32, mhMagic64:
		probe, err := readIPAThinProbe(reader, magic[:], file.UncompressedSize64)
		if err != nil {
			return false, false, err
		}
		layout, err := parseThinMachO(probe, file.UncompressedSize64)
		return true, layout.cryptID != 0, err
	default:
		return false, false, nil
	}
}

func readIPAThinProbe(reader io.Reader, magic []byte, size uint64) ([]byte, error) {
	var header [32]byte
	copy(header[:], magic)
	length := int(min(size, uint64(len(header))))
	if _, err := io.ReadFull(reader, header[len(magic):length]); err != nil {
		return nil, err
	}
	return readThinMachOProbe(reader, header[:length], size)
}

func inspectIPAFatImage(reader io.Reader, magic []byte, size uint64) (bool, error) {
	if size > math.MaxInt64 {
		return false, errors.New("universal Mach-O size exceeds supported offsets")
	}
	var table [8 + 32*32]byte
	copy(table[:], magic)
	if _, err := io.ReadFull(reader, table[4:8]); err != nil {
		return false, err
	}
	order, entrySize := fatMachOTableFormat(table[:8])
	count := int(order.Uint32(table[4:8]))
	if count == 0 || count > 32 {
		return false, errors.New("universal Mach-O architecture count is invalid")
	}
	tableSize := 8 + count*entrySize
	if _, err := io.ReadFull(reader, table[8:tableSize]); err != nil {
		return false, err
	}
	slices, err := parseFatMachOTable(table[:tableSize], size)
	if err != nil {
		return false, err
	}
	sort.Slice(slices, func(i, j int) bool { return slices[i].offset < slices[j].offset })
	position := int64(tableSize)
	encrypted := false
	for _, slice := range slices {
		offset := int64(slice.offset)
		if seeker, ok := reader.(io.Seeker); ok {
			_, err = seeker.Seek(offset, io.SeekStart)
		} else {
			_, err = io.CopyN(io.Discard, reader, offset-position)
		}
		if err != nil {
			return false, err
		}

		stream := &io.LimitedReader{R: reader, N: int64(slice.size)}
		var sliceMagic [4]byte
		if _, err := io.ReadFull(stream, sliceMagic[:]); err != nil {
			return false, err
		}
		probe, err := readIPAThinProbe(stream, sliceMagic[:], slice.size)
		if err != nil {
			return false, err
		}
		layout, err := slice.parseLayout(probe)
		if err != nil {
			return false, err
		}
		encrypted = encrypted || layout.cryptID != 0
		position = offset + int64(slice.size) - stream.N
	}
	return encrypted, nil
}
