package cmd

import (
	"context"
	"encoding/json"
	"errors"
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

// TestRun_MatchRoutingIsRespected verifies that the fan-out routing via Match
// correctly delivers each file to its appropriate detector. A vcpkg.json and
// a conanfile.txt with distinct dependencies are both present; the SBOM must
// contain a component from each, proving that Match-based routing works end-to-end.
func TestRun_MatchRoutingIsRespected(t *testing.T) {
	root := t.TempDir()

	vcpkgContent := `{"dependencies":["vcpkg-routed-dep"]}`
	if err := os.WriteFile(filepath.Join(root, "vcpkg.json"), []byte(vcpkgContent), 0o644); err != nil {
		t.Fatalf("WriteFile vcpkg.json: %v", err)
	}

	conanContent := "[requires]\nconan-routed-dep/1.0.0\n"
	if err := os.WriteFile(filepath.Join(root, "conanfile.txt"), []byte(conanContent), 0o644); err != nil {
		t.Fatalf("WriteFile conanfile.txt: %v", err)
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

	byName := make(map[string]bool, len(report.Components))
	for _, c := range report.Components {
		byName[c.Name] = true
	}

	for _, want := range []string{"vcpkg-routed-dep", "conan-routed-dep"} {
		if !byName[want] {
			t.Errorf("component %q missing from SBOM; fan-out Match routing may be broken. got: %v", want, report.Components)
		}
	}
}

// TestRun_ContextCancellation verifies that Run returns context.Canceled when
// the context is cancelled before the call. The walker checks ctx.Done on
// every entry, so a pre-cancelled context causes the walk to abort immediately
// and Run to propagate the error back to the caller.
func TestRun_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(t.TempDir(), "sbom.json")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run is called

	err := Run(ctx, &strings.Builder{}, dir, outputPath)
	if err == nil {
		t.Fatal("Run() returned nil error, want context.Canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run() error = %v, want errors.Is(err, context.Canceled) == true", err)
	}
}