// modelcheck validates only enrollment model files using the exact parser used
// by the bundled UnfairPlay revision. It never scans the host or executes models.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DrWhax/unfairplay/internal/fairplay"
)

func check(path string) (int, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("model path must not be a symlink")
	}
	paths := []string{path}
	if info.IsDir() {
		if info.Mode().Perm()&0077 != 0 {
			return 0, fmt.Errorf("model directory must be private (0700)")
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return 0, err
		}
		paths = nil
		for _, entry := range entries {
			if !strings.EqualFold(filepath.Ext(entry.Name()), ".bin") {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
				return 0, fmt.Errorf("model entry must be a regular file")
			}
			paths = append(paths, filepath.Join(path, entry.Name()))
		}
	}
	if len(paths) == 0 || len(paths) > 256 {
		return 0, fmt.Errorf("model count must be between 1 and 256")
	}
	for _, file := range paths {
		st, err := os.Lstat(file)
		if err != nil {
			return 0, err
		}
		if !st.Mode().IsRegular() || st.Size() > 16<<20 {
			return 0, fmt.Errorf("model is not a bounded regular file")
		}
		if _, err := fairplay.InspectEnrollmentModel(file); err != nil {
			return 0, err
		}
	}
	return len(paths), nil
}
func run(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("modelcheck", flag.ContinueOnError)
	flags.SetOutput(out)
	model := flags.String("model", "", "Private enrollment model file or directory")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	count, err := check(*model)
	result := map[string]any{"schema": "desk-model-check-v1", "checks": map[string]bool{"model_valid": err == nil}, "model_count": count}
	if err != nil {
		result["error"] = err.Error()
	}
	if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
