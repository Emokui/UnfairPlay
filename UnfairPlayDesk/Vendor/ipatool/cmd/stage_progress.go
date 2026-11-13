package cmd

import "time"

// Log elapsed wall time without retaining account data or adding polling.
func newStageReporter() func(string) {
	var started, previous time.Time
	return func(message string) {
		now := time.Now()
		if started.IsZero() {
			started = now
			previous = now
		}
		dependencies.Logger.Log().Str("phase", "stage").Int64("elapsed_ms", now.Sub(started).Milliseconds()).Int64("previous_stage_ms", now.Sub(previous).Milliseconds()).Msg(message)
		previous = now
	}
}
