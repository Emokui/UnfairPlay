package recovery

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
)

type frameSemanticRound struct {
	baseline [16]byte
	targets  [16][4]byte
	tables   [16][256][4]byte
}

type frameSemanticFinalByte struct {
	inputCount    byte
	inputs        [3]byte
	baseline      byte
	direct        [256]byte
	encode        [256]byte
	contributions [3][256]byte
}

type frameSemanticModel struct {
	inputConstant     [16]byte
	inputColumns      [128][16]byte
	rounds            []frameSemanticRound
	exitInputs        [4]byte
	exitBaseline      [4]byte
	exitContributions [4][4][256]byte
	final             [16]frameSemanticFinalByte
}

//go:embed profiles/macos26a428-frame-semantic.bin.gz
var frameSemanticProfileCompressed []byte

var frameSemantic26A428 = func() frameSemanticModel {
	stream, err := gzip.NewReader(bytes.NewReader(frameSemanticProfileCompressed))
	if err != nil {
		panic(fmt.Sprintf("decompress semantic frame profile: %v", err))
	}
	encoded, err := io.ReadAll(stream)
	closeErr := stream.Close()
	if err != nil || closeErr != nil {
		panic(fmt.Sprintf("decompress semantic frame profile: %v", err))
	}
	model, err := parseFrameSemanticProfile(encoded)
	clear(encoded)
	if err != nil {
		panic(fmt.Sprintf("load semantic frame profile: %v", err))
	}
	return model
}()

func parseFrameSemanticProfile(encoded []byte) (frameSemanticModel, error) {
	var result frameSemanticModel
	if len(encoded) < 32 {
		return result, fmt.Errorf("semantic frame profile is truncated")
	}
	payload, checksum := encoded[:len(encoded)-32], encoded[len(encoded)-32:]
	digest := sha256.Sum256(payload)
	if !bytes.Equal(checksum, digest[:]) {
		return result, fmt.Errorf("semantic frame profile checksum mismatch")
	}
	reader := bytes.NewReader(payload)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil || string(magic[:]) != "FPFRM1\x00\x00" {
		return result, fmt.Errorf("invalid semantic frame profile magic")
	}
	var version uint32
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil || version != 2 {
		return result, fmt.Errorf("unsupported semantic frame profile version %d", version)
	}
	if _, err := io.ReadFull(reader, result.inputConstant[:]); err != nil {
		return result, err
	}
	for index := range result.inputColumns {
		if _, err := io.ReadFull(reader, result.inputColumns[index][:]); err != nil {
			return result, err
		}
	}
	roundCount, err := reader.ReadByte()
	if err != nil || roundCount != 9 {
		return result, fmt.Errorf("invalid semantic frame round count %d", roundCount)
	}
	reserved := make([]byte, 7)
	if _, err := io.ReadFull(reader, reserved); err != nil || !bytes.Equal(reserved, make([]byte, len(reserved))) {
		return result, fmt.Errorf("invalid semantic frame round header")
	}
	result.rounds = make([]frameSemanticRound, roundCount)
	for roundIndex := range result.rounds {
		round := &result.rounds[roundIndex]
		if _, err := io.ReadFull(reader, round.baseline[:]); err != nil {
			return result, err
		}
		for position := range 16 {
			if _, err := io.ReadFull(reader, round.targets[position][:]); err != nil {
				return result, err
			}
			seen := [16]bool{}
			for _, target := range round.targets[position] {
				if target >= 16 || seen[target] {
					return result, fmt.Errorf("invalid semantic frame target")
				}
				seen[target] = true
			}
			for value := range 256 {
				if _, err := io.ReadFull(reader, round.tables[position][value][:]); err != nil {
					return result, err
				}
			}
		}
	}
	if _, err := io.ReadFull(reader, result.exitInputs[:]); err != nil {
		return result, err
	}
	for _, input := range result.exitInputs {
		if input >= 16 {
			return result, fmt.Errorf("invalid semantic frame exit input")
		}
	}
	if _, err := io.ReadFull(reader, result.exitBaseline[:]); err != nil {
		return result, err
	}
	for outputByte := range 4 {
		for slot := range 4 {
			if _, err := io.ReadFull(reader, result.exitContributions[outputByte][slot][:]); err != nil {
				return result, err
			}
		}
	}
	finalCount, err := reader.ReadByte()
	if err != nil || finalCount != 16 {
		return result, fmt.Errorf("invalid semantic frame final count %d", finalCount)
	}
	if _, err := io.ReadFull(reader, reserved); err != nil || !bytes.Equal(reserved, make([]byte, len(reserved))) {
		return result, fmt.Errorf("invalid semantic frame final header")
	}
	for target := range result.final {
		entry := &result.final[target]
		count, err := reader.ReadByte()
		if err != nil || count != 1 && count != 3 {
			return result, fmt.Errorf("invalid semantic frame final input count")
		}
		entry.inputCount = count
		if _, err := io.ReadFull(reader, entry.inputs[:]); err != nil {
			return result, err
		}
		for slot := 0; slot < int(count); slot++ {
			if entry.inputs[slot] >= 16 {
				return result, fmt.Errorf("invalid semantic frame final input")
			}
		}
		baseline, err := reader.ReadByte()
		if err != nil {
			return result, err
		}
		entry.baseline = baseline
		storedTarget, err := reader.ReadByte()
		if err != nil || storedTarget != byte(target) {
			return result, fmt.Errorf("invalid semantic frame final target")
		}
		var finalReserved [2]byte
		if _, err := io.ReadFull(reader, finalReserved[:]); err != nil || finalReserved != [2]byte{} {
			return result, fmt.Errorf("invalid semantic frame final envelope")
		}
		if count == 1 {
			if _, err := io.ReadFull(reader, entry.direct[:]); err != nil {
				return result, err
			}
		} else {
			if _, err := io.ReadFull(reader, entry.encode[:]); err != nil {
				return result, err
			}
			for slot := 0; slot < 3; slot++ {
				if _, err := io.ReadFull(reader, entry.contributions[slot][:]); err != nil {
					return result, err
				}
			}
		}
	}
	if reader.Len() != 0 {
		return result, fmt.Errorf("semantic frame profile has trailing data")
	}
	return result, nil
}

func (model frameSemanticModel) apply(input [16]byte) (output [16]byte, exitWord uint32) {
	state := model.inputConstant
	for bit, column := range model.inputColumns {
		if input[bit/8]&(byte(1)<<uint(bit%8)) != 0 {
			for index := range state {
				state[index] ^= column[index]
			}
		}
	}
	for roundIndex, round := range model.rounds {
		if roundIndex == 6 {
			for outputByte := range 4 {
				value := model.exitBaseline[outputByte]
				for slot, position := range model.exitInputs {
					value ^= model.exitContributions[outputByte][slot][state[position]]
				}
				exitWord |= uint32(value) << uint(outputByte*8)
			}
		}
		next := round.baseline
		for position, value := range state {
			for slot, target := range round.targets[position] {
				next[target] ^= round.tables[position][value][slot]
			}
		}
		state = next
	}
	for target, entry := range model.final {
		if entry.inputCount == 1 {
			output[target] = entry.direct[state[entry.inputs[0]]]
			continue
		}
		decoded := byte(0)
		for slot := 0; slot < 3; slot++ {
			decoded ^= entry.contributions[slot][state[entry.inputs[slot]]]
		}
		output[target] = entry.baseline ^ entry.encode[decoded]
	}
	return output, exitWord
}
