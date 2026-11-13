package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func synthetic(version int) []byte {
	size := 4176
	if version == 2 {
		size = 4184
	}
	if version == 3 {
		size = 8708
	}
	pack := make([]byte, size)
	copy(pack, []byte("FPSENR0\x00"))
	pack[6] = byte('0' + version)
	binary.LittleEndian.PutUint32(pack[8:12], uint32(version))
	binary.LittleEndian.PutUint32(pack[12:16], uint32(size))
	offset := 80
	if version == 2 {
		offset = 88
	}
	if version == 3 {
		offset = 84
		binary.LittleEndian.PutUint32(pack[60:64], 432)
	}
	for table := 0; table < 16; table++ {
		for value := 0; value < 256; value++ {
			pack[offset+table*256+value] = byte(value)
		}
	}
	if version == 3 {
		offset += 4096 + 432
		for table := 0; table < 16; table++ {
			for value := 0; value < 256; value++ {
				pack[offset+table*256+value] = byte(value)
			}
		}
	}
	return pack
}
func TestModelOnlyValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{1, 2, 3} {
		path := filepath.Join(dir, "model.bin")
		if err := os.WriteFile(path, synthetic(v), 0600); err != nil {
			t.Fatal(err)
		}
		if count, err := check(dir); err != nil || count != 1 {
			t.Fatalf("v%d: %d %v", v, count, err)
		}
	}
	path := filepath.Join(dir, "model.bin")
	bad := synthetic(2)
	bad[89] = bad[88]
	os.WriteFile(path, bad, 0600)
	if _, err := check(dir); err == nil {
		t.Fatal("corrupt permutation accepted")
	}
	os.WriteFile(path, synthetic(2), 0600)
	os.Chmod(path, 0644)
	if _, err := check(dir); err == nil {
		t.Fatal("public model accepted")
	}
	os.Chmod(path, 0600)
	os.Symlink(path, filepath.Join(dir, "linked.bin"))
	if _, err := check(dir); err == nil {
		t.Fatal("symlink accepted")
	}
	var out bytes.Buffer
	if run([]string{"--model", dir}, &out) == 0 {
		t.Fatal("invalid registry returned success")
	}
}
