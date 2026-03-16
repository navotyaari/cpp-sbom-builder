package detector_test

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

// fixtureDir returns the absolute path to testdata/cmake so tests are not
// tied to the working directory from which `go test` is invoked.
func fixtureDir(t *testing.T, sub string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata", sub)
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
	deps, err := d.Detect(context.Background(), root)
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

func TestCMakeDetector_Detect_NonExistentRoot(t *testing.T) {
	d := detector.CMakeDetector{}
	_, err := d.Detect(context.Background(), "/no/such/directory")
	if err == nil {
		t.Fatal("expected error for non-existent root, got nil")
	}
}

func TestCMakeDetector_Detect_ContextCancelled(t *testing.T) {
	root := fixtureDir(t, "cmake")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	d := detector.CMakeDetector{}
	_, err := d.Detect(ctx, root)
	// Either context.Canceled is returned or no results — both are acceptable.
	// The important guarantee is that it does not panic.
	_ = err
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
