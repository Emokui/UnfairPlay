package fairplay

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestIPAEncryptionStatus(t *testing.T) {
	encrypted := make([]byte, 8204)
	copy(encrypted, thinHeader(true, true))
	for _, test := range []struct {
		name      string
		image     []byte
		encrypted bool
		unknown   bool
	}{
		{"encrypted", encrypted, true, false},
		{"clear", thinHeader(false, false), false, false},
		{"unknown", []byte("not an executable"), false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "Test.ipa")
			writeMultiSINFArchive(t, file, map[string][]byte{"Payload/Test.app/Test": test.image})
			got, err := IPAHasEncryptedImages(file)
			if got != test.encrypted || (err != nil) != test.unknown {
				t.Fatalf("encrypted = %v, error = %v", got, err)
			}
		})
	}
}

func TestIPAEncryptionStatusReadsLargeUniversalImage(t *testing.T) {
	const near = 4096
	const far = 65 << 20
	const encryptedSize = 8204
	name := filepath.Join(t.TempDir(), "Large.ipa")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	archive := zip.NewWriter(file)
	defer archive.Close()
	image, err := archive.Create("Payload/Test.app/Test")
	if err != nil {
		t.Fatal(err)
	}
	table := make([]byte, 8+2*20)
	order := binary.BigEndian
	order.PutUint32(table[0:], fatMagic)
	order.PutUint32(table[4:], 2)
	// The table order is independent of the order of the slices in the file.
	order.PutUint32(table[8:], cpuTypeARM64)
	order.PutUint32(table[12:], 2)
	order.PutUint32(table[16:], far)
	order.PutUint32(table[20:], encryptedSize)
	order.PutUint32(table[24:], 12)
	order.PutUint32(table[28:], cpuTypeARM64)
	order.PutUint32(table[36:], near)
	order.PutUint32(table[40:], 32)
	order.PutUint32(table[44:], 12)
	write := func(data []byte) {
		t.Helper()
		if _, err := image.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	padding := make([]byte, 32<<10)
	pad := func(count int) {
		for count > 0 {
			chunk := min(count, len(padding))
			write(padding[:chunk])
			count -= chunk
		}
	}
	write(table)
	pad(near - len(table))
	clear := thinHeader(false, false)
	write(clear)
	pad(far - near - len(clear))
	encrypted := thinHeader(true, true)
	binary.LittleEndian.PutUint32(encrypted[8:], 2)
	write(encrypted)
	pad(encryptedSize - len(encrypted))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := IPAHasEncryptedImages(name); err != nil || !got {
		t.Fatalf("encrypted = %v, error = %v", got, err)
	}
}
