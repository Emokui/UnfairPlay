// Code generated from the compact macOS recovery profile; DO NOT EDIT.
package recovery

var compact26A428OuterHooks = []compactHook{
	{after: 0x1005D9F24, action: compactHookDigest},
	{after: 0x10058FBEC, action: compactHookOptional},
	{after: 0x1007B764C, action: compactHookEven},
	{after: 0x1003F9940, action: compactHookOdd},
	{after: 0x1004AA128, action: compactHookTail},
	{after: 0x10047EA20, action: compactHookWriter},
}

func runRawSourceOuterIteration(s *state, _ fault) error {
	kernel := compact26A428Outer
	kernel.hooks = compact26A428OuterHooks
	return runCompactKernel(s, kernel)
}
