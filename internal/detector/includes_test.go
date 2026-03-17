package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

// ── DepNameFromHeader ─────────────────────────────────────────────────────────

func TestDepNameFromHeader(t *testing.T) {
	tests := []struct {
		desc   string
		input  string
		want   string
	}{
		{
			desc:  "path with top-level directory",
			input: "openssl/ssl.h",
			want:  "openssl",
		},
		{
			desc:  "deeply nested path — only first component returned",
			input: "boost/filesystem/path.hpp",
			want:  "boost",
		},
		{
			desc:  "flat header with extension",
			input: "mylib.h",
			want:  "mylib",
		},
		{
			desc:  "flat header without extension",
			input: "mylib",
			want:  "mylib",
		},
		{
			desc:  "Windows-style backslash separator normalised",
			input: `openssl\ssl.h`,
			want:  "openssl",
		},
		{
			desc:  "mixed-case path lowercased",
			input: "OpenSSL/ssl.h",
			want:  "openssl",
		},
		{
			desc:  "mixed-case flat header lowercased",
			input: "MyLib.h",
			want:  "mylib",
		},
		{
			desc:  "empty string returns empty string",
			input: "",
			want:  "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			got := detector.DepNameFromHeader(tc.input)
			if got != tc.want {
				t.Errorf("DepNameFromHeader(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── scanFileIncludes (tested via Detect with single temp files) ───────────────

// TestIncludeScanner_AngleBracketThirdPartyDetected verifies that an
// angle-bracket include of a known third-party library is returned as a dep.
func TestIncludeScanner_AngleBracketThirdPartyDetected(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include <nlohmann/json.hpp>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := depByName(deps, "nlohmann")
	if found == nil {
		t.Fatalf("expected dep %q, not found in %v", "nlohmann", depNames(deps))
	}
}

// TestIncludeScanner_QuotedIncludeWithPathSeparatorSkipped verifies that a
// quoted include containing a path separator is treated as project-local and
// not returned as a dependency.
func TestIncludeScanner_QuotedIncludeWithPathSeparatorSkipped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	// Both forward-slash and backslash variants must be skipped.
	writeFile(t, f,
		"#include \"internal/config.h\"\n"+
			"#include \"subdir\\\\util.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d: %v", len(deps), depNames(deps))
	}
}

// TestIncludeScanner_RelativeDotSlashSkipped verifies that ./ relative paths
// are not returned as dependencies.
func TestIncludeScanner_RelativeDotSlashSkipped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include \"./local.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for ./local.h, got %d: %v", len(deps), depNames(deps))
	}
}

// TestIncludeScanner_RelativeDotDotSlashSkipped verifies that ../ relative
// paths are not returned as dependencies.
func TestIncludeScanner_RelativeDotDotSlashSkipped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include \"../parent.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for ../parent.h, got %d: %v", len(deps), depNames(deps))
	}
}

// TestIncludeScanner_KnownStdlibHeaderFilteredOut verifies that a recognised
// C++ standard-library header path is not returned as a dependency.
func TestIncludeScanner_KnownStdlibHeaderFilteredOut(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	// Several stdlib headers to be sure the filter applies broadly.
	writeFile(t, f,
		"#include <vector>\n"+
			"#include <string>\n"+
			"#include <stdio.h>\n"+
			"#include <sys/types.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d: %v", len(deps), depNames(deps))
	}
}

// TestIncludeScanner_ResolvedNameIsStdlibFiltered verifies the second stdlib
// guard: a header whose raw path is NOT in the stdlib map but whose resolved
// dep name IS in the stdlib map is still filtered out.
//
// "vector.h" is not in stdlibHeaders (the map has "vector" without the
// extension), so the first IsStdlib check passes.  depNameFromHeader strips
// the extension to produce "vector", and the second IsStdlib check on the
// resolved name catches it.
func TestIncludeScanner_ResolvedNameIsStdlibFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include <vector.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for <vector.h> (resolved name 'vector' is stdlib), got %d: %v",
			len(deps), depNames(deps))
	}
}

// TestIncludeScanner_UnreadableFileReturnsNilNoPanic verifies that a file
// which cannot be opened does not cause a panic and returns no results.
// scanFileIncludes returns nil for unreadable files; the worker swallows it.
func TestIncludeScanner_UnreadableFileReturnsNilNoPanic(t *testing.T) {
	if isWindows() {
		t.Skip("chmod 0o000 does not reliably prevent reads on Windows")
	}

	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include <openssl/ssl.h>\n")
	if err := os.Chmod(f, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(f, 0o644) })

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No deps because the file could not be read.
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for unreadable file, got %d: %v", len(deps), depNames(deps))
	}
}

// ── Detect — deduplication and evidence ──────────────────────────────────────

// TestIncludeScanner_Detect_DeduplicatesSameDep verifies that when the same
// dependency header appears in multiple files, Detect returns exactly one
// Dependency entry for that name (not one per file).
func TestIncludeScanner_Detect_DeduplicatesSameDep(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "a.cpp"),
		filepath.Join(dir, "b.cpp"),
		filepath.Join(dir, "c.h"),
	}
	for _, f := range files {
		writeFile(t, f, "#include <openssl/ssl.h>\n")
	}

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), files)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var opensslCount int
	for _, d := range deps {
		if d.Name == "openssl" {
			opensslCount++
		}
	}
	if opensslCount != 1 {
		t.Errorf("expected exactly 1 'openssl' dep, got %d", opensslCount)
	}
}

// TestIncludeScanner_Detect_EvidenceListsAllFiles verifies that when the same
// dep is found in multiple files, every file path appears in Evidence.
func TestIncludeScanner_Detect_EvidenceListsAllFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.cpp")
	b := filepath.Join(dir, "b.cpp")
	c := filepath.Join(dir, "c.hpp")
	writeFile(t, a, "#include <fmt/format.h>\n")
	writeFile(t, b, "#include <fmt/format.h>\n")
	writeFile(t, c, "#include <fmt/format.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{a, b, c})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := depByName(deps, "fmt")
	if found == nil {
		t.Fatalf("expected dep %q, not found in %v", "fmt", depNames(deps))
	}

	// All three paths must appear in Evidence (order is non-deterministic).
	evSet := make(map[string]bool, len(found.Evidence))
	for _, e := range found.Evidence {
		evSet[e] = true
	}
	for _, want := range []string{a, b, c} {
		if !evSet[want] {
			t.Errorf("Evidence missing %q; got %v", want, found.Evidence)
		}
	}
	if len(found.Evidence) != 3 {
		t.Errorf("Evidence len = %d, want 3; got %v", len(found.Evidence), found.Evidence)
	}
}

// TestIncludeScanner_Detect_CorrectFieldValues verifies that the Dependency
// fields Version, Sources, and PackageURL are set to the expected values for
// include-detected deps.
func TestIncludeScanner_Detect_CorrectFieldValues(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f, "#include <spdlog/spdlog.h>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := depByName(deps, "spdlog")
	if found == nil {
		t.Fatalf("expected dep %q, not found in %v", "spdlog", depNames(deps))
	}

	if found.Version != "unknown" {
		t.Errorf("Version = %q, want %q", found.Version, "unknown")
	}
	if len(found.Sources) != 1 || found.Sources[0] != "include" {
		t.Errorf("Sources = %v, want [include]", found.Sources)
	}
	wantPURL := detector.BuildPURL("spdlog", "unknown")
	if found.PackageURL != wantPURL {
		t.Errorf("PackageURL = %q, want %q", found.PackageURL, wantPURL)
	}
	if len(found.Evidence) == 0 {
		t.Error("Evidence is empty")
	}
}

// TestIncludeScanner_Detect_MultipleDistinctDeps verifies that distinct
// third-party headers in the same file each produce a separate Dependency.
func TestIncludeScanner_Detect_MultipleDistinctDeps(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, f,
		"#include <openssl/ssl.h>\n"+
			"#include <boost/regex.hpp>\n"+
			"#include <nlohmann/json.hpp>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := depNames(deps)
	sort.Strings(got)
	want := []string{"boost", "nlohmann", "openssl"}

	if len(got) != len(want) {
		t.Fatalf("dep count = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dep[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestIncludeScanner_Detect_ContextCancellation verifies that a context
// cancelled before Detect is called does not panic and exits cleanly.
func TestIncludeScanner_Detect_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	// Several files so the worker pool has meaningful work if it reaches them.
	for _, name := range []string{"a.cpp", "b.cpp", "c.cpp", "d.cpp", "e.cpp"} {
		writeFile(t, filepath.Join(dir, name), "#include <openssl/ssl.h>\n")
	}
	files := listFiles(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Detect is called

	s := detector.IncludeScanner{}
	// Must not panic. Error (if any) is acceptable; nil result is also fine.
	deps, err := s.Detect(ctx, files)
	_ = deps
	_ = err
}

// ── existing tests preserved ─────────────────────────────────────────────────

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
	mustPresent := []struct{ name string }{
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

func TestIncludeScanner_Detect_StdlibFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.cpp")
	writeFile(t, f, "#include <vector>\n#include <string>\n#include <iostream>\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for stdlib-only file, got %d: %v", len(deps), depNames(deps))
	}
}

func TestIncludeScanner_Detect_RelativePathsFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.cpp")
	writeFile(t, f, "#include \"./local.h\"\n#include \"../parent.h\"\n")

	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for relative includes, got %d: %v", len(deps), depNames(deps))
	}
}

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

	found := depByName(deps, "openssl")
	if found == nil {
		t.Fatal("openssl not found in deps")
	}
	if len(found.Evidence) != 2 {
		t.Errorf("Evidence len = %d, want 2; got %v", len(found.Evidence), found.Evidence)
	}
}

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
		t.Errorf("expected 0 deps from non-C++ files, got %d: %v", len(deps), depNames(deps))
	}
}

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

func TestIncludeScanner_Detect_EmptyDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := detector.IncludeScanner{}
	deps, err := s.Detect(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

// TestIncludeScanner_UnreadableFileWritesWarningToW verifies that when a source
// file cannot be opened, the warning is written to the W field and Detect still
// returns nil with zero dependencies (warn-and-continue, not abort).
func TestIncludeScanner_UnreadableFileWritesWarningToW(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 does not reliably prevent reads on Windows")
	}

	unreadable := filepath.Join(t.TempDir(), "app.cpp")
	writeFile(t, unreadable, "#include <openssl/ssl.h>\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o644) }) // allow t.TempDir cleanup

	var buf strings.Builder
	s := detector.IncludeScanner{W: &buf}
	deps, detectErr := s.Detect(context.Background(), []string{unreadable})

	if detectErr != nil {
		t.Errorf("Detect() returned error %v, want nil", detectErr)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}

	captured := buf.String()
	if !strings.Contains(captured, "include scanner: skipping") {
		t.Errorf("warning output = %q, want it to contain %q", captured, "include scanner: skipping")
	}
	if !strings.Contains(captured, unreadable) {
		t.Errorf("warning output = %q, want it to contain path %q", captured, unreadable)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// depByName returns the first Dependency with the given name, or nil.
func depByName(deps []detector.Dependency, name string) *detector.Dependency {
	for i := range deps {
		if deps[i].Name == name {
			return &deps[i]
		}
	}
	return nil
}

// depNames returns a slice of dependency names for use in error messages.
func depNames(deps []detector.Dependency) []string {
	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	return names
}

// isWindows reports whether the current OS is Windows.
func isWindows() bool {
	return filepath.Separator == '\\'
}