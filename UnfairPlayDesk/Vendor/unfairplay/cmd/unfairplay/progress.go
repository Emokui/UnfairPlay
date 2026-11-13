package main

import (
	"encoding/json"
	"github.com/DrWhax/unfairplay/internal/fairplay"
	"os"
	"time"
)

var operationStarted = time.Now()

func printOperationProgress(event fairplay.OperationProgress) {
	event.ElapsedMS = time.Since(operationStarted).Milliseconds()
	_ = json.NewEncoder(os.Stderr).Encode(event)
}
