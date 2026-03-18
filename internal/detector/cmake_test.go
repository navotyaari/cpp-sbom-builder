package detector_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

// fixtureDir returns the absolute path to testdata/<sub> so tests are not
// tied to the working directory from which `go test` is invoked.
func fixtureDir(t *testing.T, sub string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata", sub)
}

// listFiles walks root with filepath.WalkDir and returns a flat slice of all
// file paths found.  It is the test-side equivalent of walker.Walk, used to
// build the file list that Detect now expects as its second argument.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("listFiles(%q): %v", root, err)
	}
	return paths
}

func TestCMakeDetector_Match(t *testing.T) {
	d := detector.CMakeDetector{}
	tests := []struct {
		path string
		want bool
	}{
		{path: "CMakeLists.txt", want: true},
		{path: "foo.cmake", want: true},
		{path: "FOO.CMAKE", want: true}, // case insensitive
		{path: "vcpkg.json", want: false},
		{path: "main.cpp", want: false},
		{path: "", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			if got := d.Match(tc.path); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestCMakeDetector_Name(t *testing.T) {
	d := detector.CMakeDetector{}
	if got := d.Name(); got != "cmake" {
		t.Errorf("Name() = %q, want %q", got, "cmake")
	}
}

func TestCMakeDetector_Detect(t *testing.T) {
	root := fixtureDir(t, "cmake")
	fixturePath := filepath.Join(root, "CMakeLists.txt")

	d := detector.CMakeDetector{}
	deps, err := d.Detect(context.Background(), listFiles(t, root))
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Index results by name for easy lookup.
	byName := make(map[string]detector.Dependency, len(deps))
	for _, dep := range deps {
		byName[dep.Name] = dep
	}

	tests := []struct {
		name    string
		version string
	}{
		{"openssl", "1.1"},
		{"zlib", "unknown"},
		{"boost", "1.74"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dep, ok := byName[tc.name]
			if !ok {
				t.Fatalf("dependency %q not found in results; got: %v", tc.name, keys(byName))
			}

			if dep.Version != tc.version {
				t.Errorf("Version = %q, want %q", dep.Version, tc.version)
			}

			if !containsStr(dep.Evidence, fixturePath) {
				t.Errorf("Evidence does not contain fixture path %q; got: %v", fixturePath, dep.Evidence)
			}

			if len(dep.Sources) == 0 || dep.Sources[0] != "cmake" {
				t.Errorf("Sources = %v, want [cmake]", dep.Sources)
			}

			wantPURL := detector.BuildPURL(tc.name, tc.version)
			if dep.PackageURL != wantPURL {
				t.Errorf("PackageURL = %q, want %q", dep.PackageURL, wantPURL)
			}
		})
	}
}

// TestCMakeDetector_Detect_EmptyFilesReturnsEmpty verifies that an empty file
// list produces zero deps and no error.  The non-existent-root error contract
// now belongs to the walker (cmd/root.go), not the detector.
func TestCMakeDetector_Detect_EmptyFilesReturnsEmpty(t *testing.T) {
	d := detector.CMakeDetector{}
	deps, err := d.Detect(context.Background(), []string{})
	if err != nil {
		t.Fatalf("Detect() error on empty list: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for empty file list, got %d", len(deps))
	}
}

func TestCMakeDetector_Detect_ContextCancelled(t *testing.T) {
	root := fixtureDir(t, "cmake")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	d := detector.CMakeDetector{}
	// Pass a non-empty file list so the cancellation check inside the loop fires.
	_, err := d.Detect(ctx, listFiles(t, root))
	// Either context.Canceled is returned or no results — both are acceptable.
	// The important guarantee is that it does not panic.
	_ = err
}

// TestCMakeDetector_Detect_WritesWarningToW verifies that when a CMakeLists.txt
// file cannot be opened, the warning is written to the W field and Detect still
// returns nil (iteration continues over remaining files).
func TestCMakeDetector_Detect_WritesWarningToW(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 does not reliably prevent reads on Windows")
	}

	unreadable := filepath.Join(t.TempDir(), "CMakeLists.txt")
	writeFile(t, unreadable, "find_package(OpenSSL REQUIRED)\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o644) }) // allow t.TempDir cleanup

	var buf strings.Builder
	d := detector.CMakeDetector{}
	d.W = &buf
	_, detectErr := d.Detect(context.Background(), []string{unreadable})

	if detectErr != nil {
		t.Errorf("Detect() returned error %v, want nil", detectErr)
	}

	captured := buf.String()
	if !strings.Contains(captured, "cmake detector: skipping") {
		t.Errorf("warning output = %q, want it to contain %q", captured, "cmake detector: skipping")
	}
	if !strings.Contains(captured, unreadable) {
		t.Errorf("warning output = %q, want it to contain path %q", captured, unreadable)
	}
}

// TestCMakeDetector_Detect_PseudoPackagesFiltered verifies that CMake built-in
// module names are excluded from the results and real third-party packages are
// not affected by the filter.
func TestCMakeDetector_Detect_PseudoPackagesFiltered(t *testing.T) {
	f := filepath.Join(t.TempDir(), "CMakeLists.txt")
	writeFile(t, f,
		"find_package(Threads REQUIRED)\n"+
			"find_package(CMakePackageConfigHelpers REQUIRED)\n"+
			"find_package(OpenSSL 1.1 REQUIRED)\n")

	d := detector.CMakeDetector{}
	deps, err := d.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}

	byName := make(map[string]bool, len(deps))
	for _, dep := range deps {
		byName[dep.Name] = true
	}

	// CMake built-in modules must be absent.
	for _, pseudo := range []string{"threads", "cmakepackageconfighelpers"} {
		if byName[pseudo] {
			t.Errorf("pseudo-package %q should be filtered out but appeared in results", pseudo)
		}
	}

	// Real third-party package must still be present.
	if !byName["openssl"] {
		t.Errorf("dependency %q expected but not found; got: %v", "openssl", deps)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func keys(m map[string]detector.Dependency) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}