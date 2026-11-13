package fairplay

type OperationProgress struct {
	Phase     string `json:"phase"`
	Message   string `json:"message"`
	Completed int    `json:"completed,omitempty"`
	Total     int    `json:"total,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

func decryptionWarnings(verified bool) []string {
	warnings := []string{"Embedded CodeDirectory tables are checked for consistency; Apple CMS signature trust is not verified.", "Analysis IPA requires recursive re-signing before installation."}
	if !verified {
		warnings = append(warnings, "Some images have no pre-encryption hashes; ARM64 structural plausibility is not cryptographic plaintext verification.")
	}
	return warnings
}
