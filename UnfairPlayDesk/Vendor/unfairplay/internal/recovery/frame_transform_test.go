package recovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func frameTestInput(index uint32) (result [16]byte) {
	seed := append([]byte(nil), []byte("macOS FairPlay Go oracle input")...)
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], index)
	digest := sha256.Sum256(append(seed, encoded[:]...))
	copy(result[:], digest[:16])
	return result
}

func TestRecoveredFrameTransform(t *testing.T) {
	if digest := sha256.Sum256(frameSemanticProfileCompressed); hex.EncodeToString(digest[:]) != "c279626e963ba99c6760b901fa96dc232ef0d665f9f7ad83ea2087ad35ecc918" {
		t.Fatalf("semantic frame profile digest = %x", digest)
	}
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	output, err := frameTransform(value, [16]byte{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("2b7cdd00ede49ae3e3040f53c0046e65")
	if !reflect.DeepEqual(output[:], want) {
		t.Fatalf("zero frame output = %x, want %x", output, want)
	}
	if core := frameCore([16]byte{}); core != [16]byte{0x90, 0xf8, 0x3b, 0x63, 0xc1, 0xda, 0xf2, 0x88, 0x92, 0x72, 0xa7, 0xde, 0x8b, 0x4a, 0x93, 0x21} {
		t.Fatalf("zero frame core = %x", core)
	}
	for index, expected := range []string{
		"90cb4346ed4a09fc2cfb3f83680dd7f4",
		"d768891972be70c0b6cd6fb6c5219563",
		"92bf95b1688aadf7084c344aada2de32",
	} {
		output, err := frameTransform(value, frameTestInput(uint32(index)))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(output[:]); got != expected {
			t.Fatalf("deterministic frame %d = %s, want %s", index, got, expected)
		}
	}
	hash := sha256.New()
	stateHash := sha256.New()
	var exitBytes [4]byte
	for index := range 4096 {
		input := frameTestInput(uint32(index))
		output, exitWord := frameTransformState(input)
		_, _ = hash.Write(output[:])
		_, _ = stateHash.Write(output[:])
		binary.LittleEndian.PutUint32(exitBytes[:], exitWord)
		_, _ = stateHash.Write(exitBytes[:])
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != "82ec2f3bd4146e2f206043962b6c43302540c32d8cc7d9a4d54f73ad27fbe804" {
		t.Fatalf("frame corpus digest = %s", got)
	}
	if got := hex.EncodeToString(stateHash.Sum(nil)); got != "c44831133e5d50cc022097ea5b36746deeb297a182872dbb220fcabfaffd83ac" {
		t.Fatalf("frame state corpus digest = %s", got)
	}
}

func TestApplyRecoveredEnrollmentFrame(t *testing.T) {
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	worker := newState(value)
	worker.reset()
	input := frameTestInput(17)
	if err := worker.store(0x7000000fb524, input[:]); err != nil {
		t.Fatal(err)
	}
	expected, exitWord := frameTransformState(input)
	next, err := applyRecoveredEnrollmentFrame(worker)
	if err != nil {
		t.Fatal(err)
	}
	if next != 0x10030db7c || uint32(worker.x[26]) != exitWord || worker.x[4] != 0x7000000fb724 {
		t.Fatalf("frame exit = next %#x x26 %#x x4 %#x", next, worker.x[26], worker.x[4])
	}
	observed, err := worker.outputBytes(0x7000000fb724, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, expected[:]) {
		t.Fatalf("stored frame = %x, want %x", observed, expected)
	}
	if worker.n || worker.z || worker.c || worker.v {
		t.Fatal("frame exit flags are not clear")
	}
}
