package recovery

// frameRoundKeys are build-global constants, not account material. They are
// the ten independent AddRoundKey values recovered from the 26A428 frame
// mixer. This is an AES-shaped SPN, not standard AES: every round includes
// MixColumns and the keys do not use the AES schedule.
var frameRoundKeys = [10][16]byte{
	{0x45, 0xda, 0x26, 0xeb, 0x35, 0xe7, 0x30, 0x12, 0x1e, 0x00, 0x0c, 0xb3, 0x8f, 0xcb, 0xc0, 0x30},
	{0xf9, 0x6f, 0x5c, 0x1a, 0x51, 0xad, 0x34, 0xa5, 0x18, 0x91, 0x15, 0x60, 0xca, 0xc6, 0x70, 0x9c},
	{0x4f, 0x3e, 0x82, 0x6e, 0x1e, 0x93, 0xb6, 0xcb, 0x06, 0x02, 0xa3, 0xab, 0xcc, 0xc4, 0xd3, 0x37},
	{0x57, 0x58, 0x18, 0x25, 0x49, 0xcb, 0xae, 0xee, 0x4f, 0xc9, 0x0d, 0x45, 0x83, 0x0d, 0xde, 0x72},
	{0x88, 0x45, 0x58, 0xc9, 0xc1, 0x8e, 0xf6, 0x27, 0x8e, 0x47, 0xfb, 0x62, 0x0d, 0x4a, 0x25, 0x10},
	{0x4e, 0x7a, 0x92, 0x1e, 0x8f, 0xf4, 0x64, 0x39, 0x01, 0xb3, 0x9f, 0x5b, 0x0c, 0xf9, 0xba, 0x4b},
	{0xf7, 0x8e, 0x21, 0xe0, 0x78, 0x7a, 0x45, 0xd9, 0x79, 0xc9, 0xda, 0x82, 0x75, 0x30, 0x60, 0xc9},
	{0xb3, 0x5e, 0xfc, 0x7d, 0xcb, 0x24, 0xb9, 0xa4, 0xb2, 0xed, 0x63, 0x26, 0xc7, 0xdd, 0x03, 0xef},
	{0xf2, 0x25, 0x23, 0xbb, 0x39, 0x01, 0x9a, 0x1f, 0x8b, 0xec, 0xf9, 0x39, 0x4c, 0x31, 0xfa, 0xd6},
	{0x2e, 0x08, 0xd5, 0x92, 0x17, 0x09, 0x4f, 0x8d, 0x9c, 0xe5, 0xb6, 0xb4, 0xd0, 0xd4, 0x4c, 0x62},
}

var frameSBox = func() (result [256]byte) {
	for input := range 256 {
		inverse := frameGFInverse(byte(input))
		rotated, value := inverse, inverse
		for range 4 {
			rotated = rotated<<1 | rotated>>7
			value ^= rotated
		}
		result[input] = value ^ 0x63
	}
	return result
}()

func frameGFMul(left, right byte) byte {
	var result byte
	for right != 0 {
		if right&1 != 0 {
			result ^= left
		}
		high := left & 0x80
		left <<= 1
		if high != 0 {
			left ^= 0x1b
		}
		right >>= 1
	}
	return result
}

func frameGFInverse(value byte) byte {
	if value == 0 {
		return 0
	}
	result, base, exponent := byte(1), value, 254
	for exponent != 0 {
		if exponent&1 != 0 {
			result = frameGFMul(result, base)
		}
		base = frameGFMul(base, base)
		exponent >>= 1
	}
	return result
}

func frameCore(input [16]byte) [16]byte {
	state := input
	shift := [16]byte{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}
	for _, key := range frameRoundKeys {
		var substituted, mixed [16]byte
		for target, source := range shift {
			substituted[target] = frameSBox[state[source]^key[source]]
		}
		for column := range 4 {
			offset := column * 4
			a, b, c, d := substituted[offset], substituted[offset+1], substituted[offset+2], substituted[offset+3]
			mixed[offset] = frameGFMul(2, a) ^ frameGFMul(3, b) ^ c ^ d
			mixed[offset+1] = a ^ frameGFMul(2, b) ^ frameGFMul(3, c) ^ d
			mixed[offset+2] = a ^ b ^ frameGFMul(2, c) ^ frameGFMul(3, d)
			mixed[offset+3] = frameGFMul(3, a) ^ b ^ c ^ frameGFMul(2, d)
		}
		state = mixed
	}
	return state
}

func frameTransform(_ *model, input [16]byte) ([16]byte, error) {
	output, _ := frameSemantic26A428.apply(frameCore(input))
	return output, nil
}

func frameTransformState(input [16]byte) ([16]byte, uint32) {
	return frameSemantic26A428.apply(frameCore(input))
}

func applyRecoveredEnrollmentFrame(s *state) (uint64, error) {
	const inputAddress = uint64(0x7000000fb524)
	const outputAddress = uint64(0x7000000fb724)
	inputBytes, err := s.outputBytes(inputAddress, 16)
	if err != nil {
		return 0, err
	}
	var input [16]byte
	copy(input[:], inputBytes)
	output, exitWord := frameTransformState(input)
	if err := s.store(outputAddress, output[:]); err != nil {
		return 0, err
	}
	s.x = [31]uint64{0x21, 0x4b, 0x101074000, 0x7000000ffcc8, outputAddress, 0x101075b40, 0xa6, 0xa5cd4cf, 0x10030db7c, 0x5f79, 0x12, 0, 5, 0x100f4feb0, 0x5b, 0, 0x100f86660, 0x57c9, 0, 0xb1, 0x44, 0x53, 0x10105b6f0, 0x100d61250, 0x28, 0xb5, uint64(exitWord), 0x76, 0x73, 0x7000000ffdd0, 0xda}
	s.n, s.z, s.c, s.v = false, false, false, false
	return 0x10030db7c, nil
}
