package fairplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
	"testing"
)

func TestDecryptUsesIndependentPlaintextHashesForMixedCode(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		blob, layout := signedPreEncryptionAuditFixture(t, pageBytes, 2*pageBytes, 12, 2)
		layout.cpuType = cpuTypeARM64
		layout.cryptID = 1
		layout.cryptIDOffset = 16
		binary.LittleEndian.PutUint32(blob[16:20], 0)
		dir := blob[int(layout.signatureOffset)+20:]
		pre := int(binary.BigEndian.Uint32(dir[92:96]))
		for slot := 0; slot < 3; slot++ {
			h, _ := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
			copy(dir[pre+slot*32:], h)
		}
		var logical [16]byte
		logical[0] = 7
		mask := appMaskFromLogicalKey(logical)
		deriver := newPageKeyDeriver(mask)
		records := make([][32]byte, 2)
		for i := range records {
			for j := range records[i] {
				records[i][j] = byte(i*32 + j + 1)
			}
			start := (i + 1) * pageBytes
			key := deriver.pageKey(records[i][:16], uint64(start))
			block, _ := aes.NewCipher(key[:])
			cipher.NewCBCEncrypter(block, records[i][16:]).CryptBlocks(blob[start:start+pageBytes], blob[start:start+pageBytes])
		}
		binary.LittleEndian.PutUint32(blob[16:20], 1)
		if tamper {
			blob[pageBytes+8] ^= 1
		}
		// Keep the ciphertext table internally consistent so only the independent
		// plaintext table can reject a wrong decrypted page.
		for slot := 0; slot < 3; slot++ {
			h, _ := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
			copy(dir[96+slot*32:], h)
		}
		report, err := decryptImage(blob, encryptedImage{member: "Payload/Synthetic.app/Synthetic", layout: layout, sliceSize: uint64(len(blob))}, records, mask, deriver)
		if tamper {
			if err == nil || !strings.Contains(err.Error(), "plaintext page hash mismatch") {
				t.Fatalf("wrong plaintext accepted: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if report.FirstPageAudit != "code-directory-pre-encryption-hashes" || len(report.PreEncryptionCodeDirectories) != 1 || report.PreEncryptionCodeDirectories[0].MatchedSlots != 2 {
				t.Fatalf("wrong proof: %+v", report)
			}
		}
	}
}
