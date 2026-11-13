package fairplay

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyOnlyChecksIndependentHashesWithoutOutput(t *testing.T) {
	fixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	encrypted, supf, plain := multiSINFImage(t, fixture.logical, 0xd503201f)
	sigOff := 2 * pageBytes
	original := encrypted[sigOff+20:]
	dir := make([]byte, 96+4*32)
	copy(dir, original[:44])
	binary.BigEndian.PutUint32(dir[4:], uint32(len(dir)))
	binary.BigEndian.PutUint32(dir[8:], 0x20500)
	binary.BigEndian.PutUint32(dir[16:], 96)
	binary.BigEndian.PutUint32(dir[92:], 96+2*32)
	signature := make([]byte, 20)
	binary.BigEndian.PutUint32(signature, csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(signature[4:], uint32(20+len(dir)))
	binary.BigEndian.PutUint32(signature[8:], 1)
	binary.BigEndian.PutUint32(signature[16:], 20)
	encrypted = append(encrypted[:sigOff], append(signature, dir...)...)
	binary.LittleEndian.PutUint32(encrypted[68:], uint32(len(encrypted)-sigOff))
	dir = encrypted[sigOff+20:]
	for slot := 0; slot < 2; slot++ {
		cipherHash, _ := hashCodePage(2, encrypted[slot*pageBytes:(slot+1)*pageBytes])
		copy(dir[96+slot*32:], cipherHash)
		page := append([]byte(nil), encrypted[slot*pageBytes:(slot+1)*pageBytes]...)
		if slot == 0 {
			binary.LittleEndian.PutUint32(page[48:], 0)
		} else {
			copy(page, plain)
		}
		clearHash, _ := hashCodePage(2, page)
		copy(dir[160+slot*32:], clearHash)
	}
	for _, corrupt := range []bool{false, true} {
		root := t.TempDir()
		model := filepath.Join(root, "model.bin")
		if err := os.WriteFile(model, selectorBoundModelPack(t, fixture.selector), 0600); err != nil {
			t.Fatal(err)
		}
		input := filepath.Join(root, "source.ipa")
		if corrupt {
			dir[160+32] ^= 1
		}
		member := "Payload/Test.app/Test"
		writeMultiSINFArchive(t, input, map[string][]byte{member: encrypted, adjacentSINF(member): fixture.sinf, "Payload/Test.app/SC_Info/Test.supf": supf})
		result, err := VerifyIPA(DecryptOptions{InputPath: input, ModelPath: model, OutputPath: filepath.Join(root, "must-not-exist.ipa"), ReportPath: filepath.Join(root, "must-not-exist.json")})
		if corrupt {
			if err == nil || !strings.Contains(err.Error(), "plaintext page hash mismatch") {
				t.Fatalf("invalid cleartext accepted: %v", err)
			}
		} else if err != nil || !result.PlaintextVerified || result.EncryptedImages != 1 || result.DecryptedPages != 1 {
			t.Fatalf("wrong verification result: %+v %v", result, err)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatal("verification retained plaintext or report")
		}
	}
}
