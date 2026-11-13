package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPAInventoryDuplicateDirectoryMarkers(t *testing.T) {
	type zipMember struct{ name, body string }
	for _, test := range []struct {
		name, want string
		members    []zipMember
	}{
		{
			name: "empty directory markers are harmless",
			want: "contains no supported encrypted Mach-O images",
			members: []zipMember{
				{"Payload/App.app/", ""}, {"Payload/App.app/", ""},
			},
		},
		{
			name: "duplicate regular files remain rejected",
			want: `duplicate IPA member "Payload/App.app/data"`,
			members: []zipMember{
				{"Payload/App.app/data", "one"}, {"Payload/App.app/data", "two"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "App.ipa")
			output, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			archive := zip.NewWriter(output)
			for _, member := range test.members {
				writer, err := archive.Create(member.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte(member.body)); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			_, opened, err := openIPAInventory(path)
			if opened != nil {
				opened.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inventory error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestAuditARM64AcceptsARMv82HalfPrecisionSIMD(t *testing.T) {
	words := []uint32{
		0x4f001214, // fmla.8h v20, v16, v0[0]
		0x4f15127f, // fmla.8h v31, v19, v5[1]
		0x4e443694, // fmax.8h v20, v20, v4
		0x4ec537ff, // fmin.8h v31, v31, v5
	}
	page := make([]byte, pageBytes)
	for offset := 0; offset < len(page); offset += 4 {
		binary.LittleEndian.PutUint32(page[offset:offset+4], words[(offset/4)%len(words)])
	}

	valid, mnemonics := auditARM64(page)
	if valid != pageBytes/4 {
		t.Fatalf("valid ARM64 words = %d, want %d", valid, pageBytes/4)
	}
	if mnemonics["FMLA"] != 512 || mnemonics["FMAX"] != 256 || mnemonics["FMIN"] != 256 {
		t.Fatalf("unexpected mnemonic counts: %v", mnemonics)
	}
}

func TestAuditARM64AcceptsLSEAtomics(t *testing.T) {
	words := []uint32{
		0xc8a07c41, // cas x0, x1, [x2]
		0xc8e0fc41, // casal x0, x1, [x2]
		0x48207c82, // casp x0, x1, x2, x3, [x4]
		0x4860fc82, // caspal x0, x1, x2, x3, [x4]
		0xf8200041, // ldadd x0, x1, [x2]
		0xf8e02041, // ldeoral x0, x1, [x2]
		0x38a00041, // ldaddab w0, w1, [x2]
		0xf8e08041, // swpal x0, x1, [x2]
	}
	page := make([]byte, len(words)*4)
	for index, word := range words {
		binary.LittleEndian.PutUint32(page[index*4:index*4+4], word)
	}
	valid, mnemonics := auditARM64(page)
	if valid != len(words) || mnemonics["CAS"] != 2 || mnemonics["CASP"] != 2 ||
		mnemonics["LDADD"] != 2 || mnemonics["LDEOR"] != 1 || mnemonics["SWP"] != 1 {
		t.Fatalf("LSE audit = %d/%d, %#v", valid, len(words), mnemonics)
	}
}

func TestSupplementalARM64MnemonicRejectsNearbyUnallocatedEncodings(t *testing.T) {
	for _, word := range []uint32{0x4f801214, 0x4e643694, 0x4ee537ff, 0xc8a07841, 0x48207882, 0xf8209041} {
		if mnemonic, ok := supplementalARM64Mnemonic(word); ok {
			t.Errorf("%#08x unexpectedly decoded as %s", word, mnemonic)
		}
	}
}

func TestAuditARM64FirstPageUsesInstructionSections(t *testing.T) {
	page := bytes.Repeat([]byte{0xff}, pageBytes)
	const instructionOffset = 0x180
	const instructionBytes = 0x280
	for offset := instructionOffset; offset < instructionOffset+instructionBytes; offset += 4 {
		binary.LittleEndian.PutUint32(page[offset:offset+4], 0xd503201f) // nop
	}
	valid, words, mnemonics := auditARM64FirstPage(
		page,
		0x4000,
		[]machoFileRange{{offset: 0x4000 + instructionOffset, size: instructionBytes}},
	)
	if valid != instructionBytes/4 || words != instructionBytes/4 || mnemonics["NOP"] != instructionBytes/4 {
		t.Fatalf("section audit = valid %d, words %d, mnemonics %#v", valid, words, mnemonics)
	}
}

func TestAuditARM64StubHelperIgnoresLazyBindOffsets(t *testing.T) {
	page := make([]byte, pageBytes)
	binary.LittleEndian.PutUint32(page[:4], 0xd503201f) // Prologue alignment word.
	for offset := 4; offset+12 <= len(page); offset += 12 {
		binary.LittleEndian.PutUint32(page[offset:offset+4], 0x18000050)    // ldr w16, #8
		binary.LittleEndian.PutUint32(page[offset+4:offset+8], 0x14000000)  // b .
		binary.LittleEndian.PutUint32(page[offset+8:offset+12], 0x00000001) // Lazy-bind data.
	}
	ranges := []machoFileRange{{
		offset: 0x4000, size: pageBytes, segment: "__TEXT", section: "__stub_helper",
		flags: sectionAttrPureInstructions | sectionAttrSomeInstructions,
	}}
	valid, words, mnemonics := auditARM64FirstPage(page, 0x4000, ranges)
	if valid != 682 || words != 682 || mnemonics["LDR"] != 341 || mnemonics["B"] != 341 {
		t.Fatalf("stub-helper audit = %d/%d, %#v", valid, words, mnemonics)
	}

	for offset := 4; offset+12 <= len(page); offset += 12 {
		binary.LittleEndian.PutUint32(page[offset:offset+4], 0xd503201f)
	}
	valid, words, _ = auditARM64FirstPage(page, 0x4000, ranges)
	if valid*100 >= words*minimumARM64InstructionValidPercent {
		t.Fatalf("non-stub mixed page passed at %d/%d", valid, words)
	}
}

func TestFirstARM64AuditPageSkipsEncryptedDataPage(t *testing.T) {
	start, end := 0x4000, 0x40000
	ranges := []machoFileRange{{offset: 0x5d10, size: 0x32cf8}}
	page, ok := firstARM64AuditPage(start, end, ranges)
	if !ok || page != 0x5000 {
		t.Fatalf("audit page = %#x, %v; want %#x, true", page, ok, 0x5000)
	}
}

func TestAuditAdditionalARM64PagesRejectsWrongPageKey(t *testing.T) {
	const start = pageBytes
	ranges := []machoFileRange{{offset: start, size: 4 * pageBytes}}
	output := make([]byte, 5*pageBytes)
	for index := 0; index < 4; index++ {
		for offset := start + index*pageBytes; offset < start+(index+1)*pageBytes; offset += 4 {
			binary.LittleEndian.PutUint32(output[offset:offset+4], 0xd503201f) // nop
		}
	}
	if err := auditAdditionalARM64Pages(output, start, 4, 0, ranges); err != nil {
		t.Fatal(err)
	}
	for offset := start + pageBytes; offset < len(output); offset++ {
		output[offset] = 0xff
	}
	if err := auditAdditionalARM64Pages(output, start, 4, 0, ranges); err == nil {
		t.Fatal("invalid later code pages were accepted")
	}
}

func TestDecryptRejectsMixedInstructionPageWithDiagnostics(t *testing.T) {
	blob, layout := signedAuditFixture(t, pageBytes, pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM64
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	layout.instructionRanges = []machoFileRange{{
		offset: pageBytes, size: 598 * 4, segment: "__TEXT", section: "__mixed",
		flags: sectionAttrSomeInstructions,
	}}
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	var record [32]byte
	for index := range record {
		record[index] = byte(0x40 + index)
	}
	plaintext := bytes.Repeat([]byte{0xff}, pageBytes)
	for offset := 0; offset < 409*4; offset += 4 {
		binary.LittleEndian.PutUint32(plaintext[offset:offset+4], 0xd503201f)
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	key := deriver.pageKey(record[:16], pageBytes)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCEncrypter(block, record[16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plaintext)
	clear(key[:])

	directory := blob[int(layout.signatureOffset)+20:]
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[44+slot*32:], hash)
	}

	image := encryptedImage{member: "Payload/Test.app/Test", layout: layout, sliceSize: uint64(len(blob))}
	_, err = decryptImage(blob, image, [][32]byte{record}, mask, deriver)
	if err == nil {
		t.Fatal("mixed instruction page passed the structural audit")
	}
	for _, want := range []string{"409/598", "__TEXT,__mixed", "full-page=none", "offset-trials=[absolute-per-page=409/598"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("diagnostic error %q does not contain %q", err, want)
		}
	}
}

func TestDecryptUniversalSliceUsesEachPageOffset(t *testing.T) {
	blob, layout := signedAuditFixture(t, pageBytes, 2*pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM64
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	layout.instructionRanges = []machoFileRange{{offset: uint64(layout.cryptOffset), size: uint64(layout.cryptSize)}}
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	image := encryptedImage{
		member: "Payload/Test.app/Test", supfMember: "Payload/Test.app/SC_Info/Test.supf",
		sliceOffset: 0x4000, sliceSize: uint64(len(blob)), layout: layout,
	}
	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	records := make([][32]byte, 2)
	for page := range records {
		for index := range records[page] {
			records[page][index] = byte(0x40 + page*len(records[page]) + index)
		}
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	plaintext := make([]byte, 2*pageBytes)
	for page := range records {
		key := deriver.pageKey(
			records[page][:16],
			image.sliceOffset+uint64(layout.cryptOffset)+uint64(page*pageBytes),
		)
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		start := int(layout.cryptOffset) + page*pageBytes
		cipher.NewCBCEncrypter(block, records[page][16:]).CryptBlocks(
			blob[start:start+pageBytes], plaintext[page*pageBytes:(page+1)*pageBytes],
		)
	}

	directory := blob[int(layout.signatureOffset)+20:]
	hashOffset, hashSize := 44, 32
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[hashOffset+slot*hashSize:], hash)
	}

	encryptedHash := digest(blob)
	report, err := decryptImage(blob, image, records, mask, deriver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[pageBytes:3*pageBytes], plaintext) {
		t.Fatal("universal slice did not decrypt with each encrypted page offset")
	}
	if report.EncryptedSHA256 != encryptedHash || report.DecryptedSHA256 != digest(blob) {
		t.Fatalf("unexpected image hashes: %+v", report)
	}
	if report.Architecture != "arm64" || report.FirstPageAudit != "arm64-instruction-decode" || !report.FirstPageStructurallyPlausible {
		t.Fatalf("unexpected report: %+v", report)
	}
}
