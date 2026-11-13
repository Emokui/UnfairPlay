// Code generated from the validated macOS 26A428 recovery profile; DO NOT EDIT.
package recovery

func runRawSourceBootstrapKernel(s *state, _ fault) error {
	return runCompactKernel(s, compact26A428BootstrapKernel)
}
