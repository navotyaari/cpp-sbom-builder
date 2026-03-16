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
	deps, err := s.Detect(context.Background(), root)
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
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.cpp"),
		"#include <vector>\n#include <string>\n#include <iostream>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
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
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.cpp"),
		"#include \"./local.h\"\n#include \"../parent.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
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
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "app.cpp"),
		"#include <nlohmann/json.hpp>\n#include <spdlog/spdlog.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
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
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.cpp"), "#include <openssl/ssl.h>\n")
	writeFile(t, filepath.Join(root, "b.cpp"), "#include <openssl/ssl.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
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
	root := t.TempDir()
	// .go file with a fake #include — must be ignored.
	writeFile(t, filepath.Join(root, "main.go"), "#include <openssl/ssl.h>\n")
	// Python file — also ignored.
	writeFile(t, filepath.Join(root, "helper.py"), "#include <boost/regex.hpp>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps from non-C++ files, got %d: %v", len(deps), deps)
	}
}

// TestIncludeScanner_Detect_NonExistentRoot checks the error contract.
func TestIncludeScanner_Detect_NonExistentRoot(t *testing.T) {
	s := detector.IncludeScanner{}
	_, err := s.Detect(context.Background(), "/no/such/path/includes")
	if err == nil {
		t.Fatal("expected error for non-existent root, got nil")
	}
}

// TestIncludeScanner_Detect_EmptyDir returns no deps and no error.
func TestIncludeScanner_Detect_EmptyDir(t *testing.T) {
	root := t.TempDir()
	// Add a sub-dir with no C++ files.
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}
