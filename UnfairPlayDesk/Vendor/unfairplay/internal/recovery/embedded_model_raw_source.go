package recovery

import _ "embed"

// rawSourceModel contains only build-global state before the installed SINF
// and SUPF are opened. Its executable-path page is zero and supplied by the
// caller at runtime.
//
//go:embed profiles/macos26a428-account-entry-public.model.gz
var rawSourceModel []byte

func embeddedModelBytes() []byte { return rawSourceModel }
