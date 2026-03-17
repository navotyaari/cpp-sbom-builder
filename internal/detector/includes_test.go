package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

func TestIncludeScanner_Name(t *testing.T) {
	s := detector.IncludeScanner{}
	if got := s.Name(); got != "include" {
		t.Errorf("Name() = %q, want %q", got, "include")
	}
}

func TestIncludeScanner_Detect_Fixture(t *testing.T) {
	root := fixtureDir(t, "includes")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), listFiles(t, root))
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}

	byName := make(map[string]detector.Dependency, len(deps))
	for _, dep := range deps {
		byName[dep.Name] = dep
	}

	// ── Must NOT appear ───────────────────────────────────────────────────────
	mustAbsent := []string{"vector", "string", "iostream", "internal"}
	for _, name := range mustAbsent {
		if _, found := byName[name]; found {
			t.Errorf("dependency %q should be filtered out but was returned", name)
		}
	}

	// ── Must appear ───────────────────────────────────────────────────────────
	mustPresent := []struct {
		name string
	}{
		{"openssl"},
		{"boost"},
	}
	for _, tc := range mustPresent {
		dep, found := byName[tc.name]
		if !found {
			t.Errorf("dependency %q expected but not found; got keys: %v", tc.name, keys(byName))
			continue
		}
		if dep.Version != "unknown" {
			t.Errorf("%s: Version = %q, want %q", tc.name, dep.Version, "unknown")
		}
		if len(dep.Sources) == 0 || dep.Sources[0] != "include" {
			t.Errorf("%s: Sources = %v, want [include]", tc.name, dep.Sources)
		}
		if len(dep.Evidence) == 0 {
			t.Errorf("%s: Evidence is empty", tc.name)
		}
	}
}

// TestIncludeScanner_Detect_StdlibFiltered confirms stdlib headers are dropped.
func TestIncludeScanner_Detect_StdlibFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.cpp")
	writeFile(t, f, "#include <vector>\n#include <string>\n#include <iostream>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for stdlib-only file, got %d: %v", len(deps), deps)
	}
}

// TestIncludeScanner_Detect_RelativePathsFiltered confirms ./ and ../ headers
// are not returned as dependencies.
func TestIncludeScanner_Detect_RelativePathsFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.cpp")
	writeFile(t, f, "#include \"./local.h\"\n#include \"../parent.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for relative includes, got %d: %v", len(deps), deps)
	}
}

// TestIncludeScanner_Detect_TopLevelDirExtracted confirms the top-level
// directory component is used as the dep name for path-style headers.
func TestIncludeScanner_Detect_TopLevelDirExtracted(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include <nlohmann/json.hpp>\n#include <spdlog/spdlog.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byName := make(map[string]bool, len(deps))
	for _, d := range deps {
		byName[d.Name] = true
	}

	for _, want := range []string{"nlohmann", "spdlog"} {
		if !byName[want] {
			t.Errorf("expected dep %q, not found; got: %v", want, deps)
		}
	}
}

// TestIncludeScanner_Detect_EvidenceAcrossFiles confirms that when the same
// dep appears in multiple files it is merged into one entry with both paths
// in Evidence.
func TestIncludeScanner_Detect_EvidenceAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.cpp")
	b := filepath.Join(dir, "b.cpp")
	writeFile(t, a, "#include <openssl/ssl.h>\n")
	writeFile(t, b, "#include <openssl/ssl.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{a, b})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var found *detector.Dependency
	for i := range deps {
		if deps[i].Name == "openssl" {
			found = &deps[i]
			break
		}
	}
	if found == nil {
		t.Fatal("openssl not found in deps")
	}
	if len(found.Evidence) != 2 {
		t.Errorf("Evidence len = %d, want 2; got %v", len(found.Evidence), found.Evidence)
	}
}

// TestIncludeScanner_Detect_OnlyCppExtensions confirms that non-C++ files are
// not processed.
func TestIncludeScanner_Detect_OnlyCppExtensions(t *testing.T) {
	dir := t.TempDir()
	goFile := filepath.Join(dir, "main.go")
	pyFile := filepath.Join(dir, "helper.py")
	writeFile(t, goFile, "#include <openssl/ssl.h>\n")
	writeFile(t, pyFile, "#include <boost/regex.hpp>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{goFile, pyFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps from non-C++ files, got %d: %v", len(deps), deps)
	}
}

// TestIncludeScanner_Detect_EmptyFilesReturnsEmpty verifies that an empty file
// list produces zero deps and no error.  The non-existent-root error contract
// now belongs to the walker (cmd/root.go), not the detector.
func TestIncludeScanner_Detect_EmptyFilesReturnsEmpty(t *testing.T) {
	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

// TestIncludeScanner_Detect_EmptyDir returns no deps and no error when the
// file list contains only non-C++ files.
func TestIncludeScanner_Detect_EmptyDir(t *testing.T) {
	root := t.TempDir()
	// Add a sub-dir with no C++ files.
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Walk yields the docs dir's contents (none) — simulate with empty list.
	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}