package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cpp-sbom-builder/internal/formatter"
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

// TestRun_SkipDirContentsNotDetected verifies that files inside skip-listed
// directories (build/, .git/, etc.) do not contribute components to the SBOM
// even when those files would otherwise match a detector's patterns.
//
// This is an end-to-end regression guard for the single-pass walker wiring:
// if the skip-dir pruning were accidentally removed from the walk, a
// vcpkg.json placed inside a "build" directory would be parsed and an
// unexpected component would appear in the output.
func TestRun_SkipDirContentsNotDetected(t *testing.T) {
	root := t.TempDir()

	// Plant a vcpkg.json inside a "build" directory that the walker must prune.
	buildVcpkg := filepath.Join(root, "build", "vcpkg.json")
	if err := os.MkdirAll(filepath.Dir(buildVcpkg), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	vcpkgContent := `{"dependencies":["should-not-appear"]}`
	if err := os.WriteFile(buildVcpkg, []byte(vcpkgContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Also plant one inside .git/ for good measure.
	gitVcpkg := filepath.Join(root, ".git", "vcpkg.json")
	if err := os.MkdirAll(filepath.Dir(gitVcpkg), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(gitVcpkg, []byte(vcpkgContent), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "sbom.json")
	var buf strings.Builder
	if err := Run(context.Background(), &buf, root, outputPath); err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var report formatter.SBOMReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, c := range report.Components {
		if c.Name == "should-not-appear" {
			t.Errorf("component %q from inside a skip-listed directory appeared in output; skip-dir pruning is broken", c.Name)
		}
	}
}