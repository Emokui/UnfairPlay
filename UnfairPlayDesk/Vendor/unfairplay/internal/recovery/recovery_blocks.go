package recovery

func recoveryBlock(s *state, pc uint64, primary, supplemental, verifiedFallback map[uint64]compactBlock) (compactBlock, bool) {
	if block, ok := primary[pc]; ok {
		return block, true
	}
	if block, ok := supplemental[pc]; ok {
		return block, true
	}
	if block, ok := verifiedFallback[pc]; ok {
		return block, true
	}
	if block, ok := s.model.exactExtractedBlocks[pc]; ok {
		s.extractedBlockHits++
		return block, true
	}
	return compactBlock{}, false
}

func recoverySINFEntryBlock(s *state, profile *executionProfile, pc uint64) (compactBlock, bool) {
	if block, ok := profile.sinfEntryBlock(pc); ok {
		return block, true
	}
	if block, ok := profile.supplementalBlocks[pc]; ok {
		return block, true
	}
	if block, ok := profile.verifiedFallbackBlocks[pc]; ok {
		return block, true
	}
	if block, ok := s.model.exactExtractedBlocks[pc]; ok {
		s.extractedBlockHits++
		return block, true
	}
	return compactBlock{}, false
}
