package recovery

import (
	"reflect"
	"testing"
	"unsafe"
)

func TestCompactKernelEncoding(t *testing.T) {
	if size := unsafe.Sizeof(compactInstruction{}); size != 10 {
		t.Fatalf("compact instruction size = %d, want 10", size)
	}
	for name, kernel := range map[string]compactKernel{
		"bootstrap":       compact26A428BootstrapKernel,
		"digest-prologue": compact26A428DigestPrologue,
		"cycle-final":     compact26A428CycleFinal,
		"optional":        compact26A428Optional,
		"even":            compact26A428Even,
		"odd":             compact26A428Odd,
		"tail":            compact26A428Tail,
		"writer":          compact26A428Writer,
		"digest":          compact26A428Digest,
		"cycle":           compact26A428Cycle,
		"outer":           compact26A428Outer,
	} {
		if kernel.start == 0 || len(kernel.instructions) == 0 {
			t.Fatalf("%s kernel is empty", name)
		}
		for index, instruction := range kernel.instructions {
			if instruction.op >= compactOpcodeCount {
				t.Fatalf("%s instruction %d has opcode %d", name, index, instruction.op)
			}
		}
	}
	if got := len(compact26A428BootstrapKernel.instructions); got != 31 {
		t.Fatalf("bootstrap instruction count = %d, want 31", got)
	}
	if got := len(compact26A428DigestPrologue.instructions); got != 13 {
		t.Fatalf("digest prologue instruction count = %d, want 13", got)
	}
	if got := len(compact26A428CycleFinal.instructions); got != 69 {
		t.Fatalf("cycle final instruction count = %d, want 69", got)
	}
	if got := len(compact26A428Optional.instructions); got != 117 {
		t.Fatalf("optional instruction count = %d, want 117", got)
	}
	if got := len(compact26A428Even.instructions); got != 220 {
		t.Fatalf("even instruction count = %d, want 220", got)
	}
	if got := len(compact26A428Odd.instructions); got != 311 {
		t.Fatalf("odd instruction count = %d, want 311", got)
	}
	if got := len(compact26A428Tail.instructions); got != 452 {
		t.Fatalf("tail instruction count = %d, want 452", got)
	}
	if got := len(compact26A428Writer.instructions); got != 651 {
		t.Fatalf("writer instruction count = %d, want 651", got)
	}
	if got := len(compact26A428Digest.instructions); got != 1718 {
		t.Fatalf("digest instruction count = %d, want 1718", got)
	}
	if got := len(compact26A428Cycle.instructions); got != 1716 {
		t.Fatalf("cycle instruction count = %d, want 1716", got)
	}
	if got := len(compact26A428Outer.instructions); got != 35206 {
		t.Fatalf("outer instruction count = %d, want 35206", got)
	}
	if got := len(compact26A428Outer.segments); got != 36 {
		t.Fatalf("outer segment count = %d, want 36", got)
	}
	if got := len(compact26A428OuterHooks); got != 6 {
		t.Fatalf("outer hook count = %d, want 6", got)
	}
}

func TestCompactProfileBinaryRoundTrip(t *testing.T) {
	sections := []compactProfileSection{
		{id: 1, blocks: compact26A428AccountEntryBlocks},
		{id: 2, blocks: compact26A428BootstrapBlocks},
		{id: 3, blocks: compact26A428SelectionBlocks},
		{id: 4, blocks: compact26A428SINFEntryBlocks00},
		{id: 5, blocks: compact26A428SINFEntryBlocks01},
		{id: 6, blocks: compact26A428SINFEntryBlocks02},
		{id: 7, blocks: compact26A428SINFEntryBlocks03},
		{id: 8, blocks: compact26A428SINFEntryBlocks04},
		{id: 9, blocks: compact26A428SINFEntryBlocks05},
	}
	encoded, err := marshalCompactProfile(sections)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalCompactProfile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range sections {
		if !reflect.DeepEqual(decoded[section.id], section.blocks) {
			t.Fatalf("compact profile section %d changed after round trip", section.id)
		}
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := unmarshalCompactProfile(encoded); err == nil {
		t.Fatal("corrupt compact profile was accepted")
	}
}

func TestCompactBlockControlFlowAndStop(t *testing.T) {
	s := newState(&model{pages: make(map[uint64][]byte)})
	block := compactBlock{
		start: 0x1000,
		instructions: []compactInstruction{
			{op: compactMovImm32, destination: 1, immediate: 7},
			{op: compactCmpImm32, left: 1, immediate: 8},
		},
		terminator: compactBlockConditional,
		condition:  compactConditionNE,
		target:     0x2000,
		alternate:  0x100c,
	}
	next, stopped, err := runCompactBlock(s, nil, block)
	if err != nil || stopped || next != 0x2000 {
		t.Fatalf("conditional block = next %#x, stopped %t, err %v", next, stopped, err)
	}

	s = newState(&model{pages: make(map[uint64][]byte)})
	next, stopped, err = runCompactBlock(s, &rawSourceRuntime{stopPC: 0x1004}, block)
	if err != nil || !stopped || next != 0x1004 || s.x[1] != 7 {
		t.Fatalf("stopped block = next %#x, stopped %t, x1 %#x, err %v", next, stopped, s.x[1], err)
	}
}

func TestCompactAccountEntryBlocks(t *testing.T) {
	if got := len(compact26A428AccountEntryBlocks); got != 1086 {
		t.Fatalf("compact account-entry block count = %d, want 1086", got)
	}
	for address, block := range compact26A428AccountEntryBlocks {
		if block.start != address {
			t.Fatalf("account-entry block %#x starts at %#x", address, block.start)
		}
		for index, instruction := range block.instructions {
			if instruction.op >= compactOpcodeCount {
				t.Fatalf("account-entry block %#x instruction %d has opcode %d", address, index, instruction.op)
			}
		}
	}
}

func TestCompactBootstrapBlocks(t *testing.T) {
	if got := len(compact26A428BootstrapBlocks); got != 953 {
		t.Fatalf("compact bootstrap block count = %d, want 953", got)
	}
	for address, block := range compact26A428BootstrapBlocks {
		if block.start != address {
			t.Fatalf("bootstrap block %#x starts at %#x", address, block.start)
		}
	}
}

func TestCompactSelectionBlocks(t *testing.T) {
	if got := len(compact26A428SelectionBlocks); got != 1656 {
		t.Fatalf("compact selection block count = %d, want 1656", got)
	}
	for address, block := range compact26A428SelectionBlocks {
		if block.start != address {
			t.Fatalf("selection block %#x starts at %#x", address, block.start)
		}
	}
}

func TestCompactSINFEntryBlocks(t *testing.T) {
	total := 0
	for _, blocks := range []map[uint64]compactBlock{
		compact26A428SINFEntryBlocks00,
		compact26A428SINFEntryBlocks01,
		compact26A428SINFEntryBlocks02,
		compact26A428SINFEntryBlocks03,
		compact26A428SINFEntryBlocks04,
		compact26A428SINFEntryBlocks05,
	} {
		total += len(blocks)
		for address, block := range blocks {
			if block.start != address {
				t.Fatalf("SINF-entry block %#x starts at %#x", address, block.start)
			}
		}
	}
	if total != 1890 {
		t.Fatalf("compact SINF-entry block count = %d, want 1890", total)
	}
}

func TestCompactPairAddressing(t *testing.T) {
	value := &model{pages: make(map[uint64][]byte)}
	s := newState(value)
	s.sp = 0x1000
	if err := s.mapZero(0x1000, pageSize); err != nil {
		t.Fatal(err)
	}
	if err := s.storeValue(0x1050, 0x1122334455667788, 8); err != nil {
		t.Fatal(err)
	}
	if err := s.storeValue(0x1058, 0x99aabbccddeeff00, 8); err != nil {
		t.Fatal(err)
	}
	kernel := compactKernel{start: 0x2000, instructions: []compactInstruction{{
		op: compactPairLoad64, destination: 29, left: 31, right: 30, immediate: 0x50,
	}}}
	if err := runCompactKernel(s, kernel); err != nil {
		t.Fatal(err)
	}
	if s.x[29] != 0x1122334455667788 || s.x[30] != 0x99aabbccddeeff00 || s.sp != 0x1000 {
		t.Fatalf("pair load = x29 %#x, x30 %#x, sp %#x", s.x[29], s.x[30], s.sp)
	}
}

func TestCompactSelectZeroRegister(t *testing.T) {
	s := newState(&model{pages: make(map[uint64][]byte)})
	s.x[12] = 0x100000000
	s.c = true
	kernel := compactKernel{start: 0x3000, instructions: []compactInstruction{{
		op: compactCSEL64, destination: 12, left: 12, right: 31, shift: uint8(compactConditionLO),
	}}}
	if err := runCompactKernel(s, kernel); err != nil {
		t.Fatal(err)
	}
	if s.x[12] != 0 {
		t.Fatalf("CSEL zero register result = %#x", s.x[12])
	}
}
