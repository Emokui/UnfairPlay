package recovery

func shiftLeft(value uint64, amount, width int) uint64 {
	if width == 32 {
		return uint64(uint32(value) << (uint(amount) & 31))
	}
	return value << (uint(amount) & 63)
}

func shiftRight(value uint64, amount, width int) uint64 {
	if width == 32 {
		return uint64(uint32(value) >> (uint(amount) & 31))
	}
	return value >> (uint(amount) & 63)
}

func shiftRightArithmetic(value uint64, amount, width int) uint64 {
	if width == 32 {
		return uint64(uint32(int32(value) >> (uint(amount) & 31)))
	}
	return uint64(int64(value) >> (uint(amount) & 63))
}

func rotateRight(value uint64, amount, width int) uint64 {
	if width == 32 {
		return uint64(rotateRight32(uint32(value), uint32(amount)))
	}
	amount &= 63
	if amount == 0 {
		return value
	}
	return value>>amount | value<<(64-amount)
}

func bitMask(bits, width int) uint64 {
	if bits >= width {
		if width == 32 {
			return uint64(^uint32(0))
		}
		return ^uint64(0)
	}
	return uint64(1)<<bits - 1
}

func insertBits(destination, source uint64, lsb, bits, width int) uint64 {
	mask := bitMask(bits, width) << lsb
	value := (destination &^ mask) | ((source << lsb) & mask)
	if width == 32 {
		return uint64(uint32(value))
	}
	return value
}

func extractPair(high, low uint64, amount, width int) uint64 {
	if width == 32 {
		combined := uint64(uint32(high))<<32 | uint64(uint32(low))
		return uint64(uint32(combined >> amount))
	}
	if amount == 0 {
		return low
	}
	return high<<(64-amount) | low>>amount
}

func addOffset(value uint64, offset int64) uint64 { return value + uint64(offset) }

func boolValue(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func selectValue(condition bool, left, right uint64) uint64 {
	if condition {
		return left
	}
	return right
}
