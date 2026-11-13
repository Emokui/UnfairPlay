package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	compactProfileMagic   = "FPCFG1\x00\x00"
	compactProfileVersion = uint32(1)
)

type compactProfileSection struct {
	id     uint8
	blocks map[uint64]compactBlock
}

func marshalCompactProfile(sections []compactProfileSection) ([]byte, error) {
	if len(sections) == 0 || len(sections) > 255 {
		return nil, fmt.Errorf("invalid compact profile section count %d", len(sections))
	}
	var output bytes.Buffer
	output.WriteString(compactProfileMagic)
	_ = binary.Write(&output, binary.LittleEndian, compactProfileVersion)
	_ = binary.Write(&output, binary.LittleEndian, uint32(len(sections)))
	seenSections := make(map[uint8]bool, len(sections))
	for _, section := range sections {
		if section.id == 0 || seenSections[section.id] || len(section.blocks) == 0 {
			return nil, fmt.Errorf("invalid compact profile section %d", section.id)
		}
		seenSections[section.id] = true
		output.WriteByte(section.id)
		output.Write(make([]byte, 7))
		_ = binary.Write(&output, binary.LittleEndian, uint32(len(section.blocks)))
		_ = binary.Write(&output, binary.LittleEndian, uint32(0))
		addresses := make([]uint64, 0, len(section.blocks))
		for address := range section.blocks {
			addresses = append(addresses, address)
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
		for _, address := range addresses {
			block := section.blocks[address]
			if block.start != address || block.terminator > compactBlockStopDirect || len(block.instructions) > int(^uint32(0)) {
				return nil, fmt.Errorf("invalid compact block %#x", address)
			}
			_ = binary.Write(&output, binary.LittleEndian, address)
			output.Write([]byte{byte(block.terminator), byte(block.condition), block.register, block.width, block.bit, 0, 0, 0})
			_ = binary.Write(&output, binary.LittleEndian, block.target)
			_ = binary.Write(&output, binary.LittleEndian, block.alternate)
			_ = binary.Write(&output, binary.LittleEndian, uint32(len(block.instructions)))
			_ = binary.Write(&output, binary.LittleEndian, uint32(0))
			for _, instruction := range block.instructions {
				if instruction.op >= compactOpcodeCount {
					return nil, fmt.Errorf("compact block %#x has invalid opcode %d", address, instruction.op)
				}
				_ = binary.Write(&output, binary.LittleEndian, uint16(instruction.op))
				output.Write([]byte{instruction.destination, instruction.left, instruction.right, instruction.accumulator, instruction.shift, 0})
				_ = binary.Write(&output, binary.LittleEndian, instruction.immediate)
			}
		}
	}
	encoded := output.Bytes()
	digest := sha256.Sum256(encoded)
	return append(encoded, digest[:]...), nil
}

func unmarshalCompactProfile(input []byte) (map[uint8]map[uint64]compactBlock, error) {
	if len(input) < 32 {
		return nil, fmt.Errorf("compact profile is truncated")
	}
	payload, checksum := input[:len(input)-32], input[len(input)-32:]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(checksum, digest[:]) {
		return nil, fmt.Errorf("compact profile checksum mismatch")
	}
	reader := bytes.NewReader(payload)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || string(magic[:]) != compactProfileMagic {
		return nil, fmt.Errorf("invalid compact profile magic")
	}
	var version, sectionCount uint32
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil || version != compactProfileVersion {
		return nil, fmt.Errorf("unsupported compact profile version %d", version)
	}
	if err := binary.Read(reader, binary.LittleEndian, &sectionCount); err != nil || sectionCount == 0 || sectionCount > 255 {
		return nil, fmt.Errorf("invalid compact profile section count %d", sectionCount)
	}
	sections := make(map[uint8]map[uint64]compactBlock, sectionCount)
	readReserved := func(size int) error {
		reserved := make([]byte, size)
		if _, err := io.ReadFull(reader, reserved); err != nil {
			return err
		}
		if !bytes.Equal(reserved, make([]byte, size)) {
			return fmt.Errorf("compact profile reserved bytes are nonzero")
		}
		return nil
	}
	for sectionIndex := uint32(0); sectionIndex < sectionCount; sectionIndex++ {
		id, err := reader.ReadByte()
		if err != nil || id == 0 || sections[id] != nil {
			return nil, fmt.Errorf("invalid compact profile section identifier")
		}
		if err := readReserved(7); err != nil {
			return nil, err
		}
		var blockCount, reserved uint32
		if err := binary.Read(reader, binary.LittleEndian, &blockCount); err != nil || blockCount == 0 {
			return nil, fmt.Errorf("invalid compact profile block count")
		}
		if err := binary.Read(reader, binary.LittleEndian, &reserved); err != nil || reserved != 0 {
			return nil, fmt.Errorf("invalid compact profile section header")
		}
		blocks := make(map[uint64]compactBlock, blockCount)
		previous := uint64(0)
		for blockIndex := uint32(0); blockIndex < blockCount; blockIndex++ {
			var address uint64
			if err := binary.Read(reader, binary.LittleEndian, &address); err != nil || address == 0 || blockIndex != 0 && address <= previous {
				return nil, fmt.Errorf("compact profile block addresses are invalid")
			}
			previous = address
			control := make([]byte, 8)
			if _, err := io.ReadFull(reader, control); err != nil || control[0] > byte(compactBlockStopDirect) || control[5] != 0 || control[6] != 0 || control[7] != 0 {
				return nil, fmt.Errorf("compact block %#x has invalid control data", address)
			}
			block := compactBlock{
				start: address, terminator: compactBlockTerminator(control[0]), condition: compactCondition(control[1]),
				register: control[2], width: control[3], bit: control[4],
			}
			if err := binary.Read(reader, binary.LittleEndian, &block.target); err != nil {
				return nil, err
			}
			if err := binary.Read(reader, binary.LittleEndian, &block.alternate); err != nil {
				return nil, err
			}
			var instructionCount uint32
			if err := binary.Read(reader, binary.LittleEndian, &instructionCount); err != nil {
				return nil, err
			}
			if err := binary.Read(reader, binary.LittleEndian, &reserved); err != nil || reserved != 0 {
				return nil, fmt.Errorf("compact block %#x has invalid header", address)
			}
			block.instructions = make([]compactInstruction, instructionCount)
			for index := range block.instructions {
				var opcode uint16
				if err := binary.Read(reader, binary.LittleEndian, &opcode); err != nil || compactOpcode(opcode) >= compactOpcodeCount {
					return nil, fmt.Errorf("compact block %#x has invalid instruction opcode", address)
				}
				operands := make([]byte, 6)
				if _, err := io.ReadFull(reader, operands); err != nil || operands[5] != 0 {
					return nil, fmt.Errorf("compact block %#x has invalid instruction operands", address)
				}
				instruction := compactInstruction{
					op: compactOpcode(opcode), destination: operands[0], left: operands[1], right: operands[2],
					accumulator: operands[3], shift: operands[4],
				}
				if err := binary.Read(reader, binary.LittleEndian, &instruction.immediate); err != nil {
					return nil, err
				}
				block.instructions[index] = instruction
			}
			blocks[address] = block
		}
		sections[id] = blocks
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("compact profile has trailing data")
	}
	return sections, nil
}
