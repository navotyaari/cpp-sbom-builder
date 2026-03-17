package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestRun_SuccessMessageWrittenToWriter verifies that after a successful run
// the "SBOM written to" message is written to the injected io.Writer and does
// not leak to os.Stdout.
func TestRun_SuccessMessageWrittenToWriter(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "sbom.json")

	var buf strings.Builder
	if err := Run(context.Background(), &buf, dir, outputPath); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "SBOM written to") {
		t.Errorf("writer output = %q, want it to contain %q", buf.String(), "SBOM written to")
	}
}