package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

func TestConanDetector_Match(t *testing.T) {
	d := detector.ConanDetector{}
	tests := []struct {
		path string
		want bool
	}{
		{path: "conanfile.txt", want: true},
		{path: "conanfile.py", want: false},
		{path: "CMakeLists.txt", want: false},
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

func TestConanDetector_Name(t *testing.T) {
	d := detector.ConanDetector{}
	if got := d.Name(); got != "conan" {
		t.Errorf("Name() = %q, want %q", got, "conan")
	}
}

func TestConanDetector_Detect_Fixture(t *testing.T) {
	root := fixtureDir(t, "conan")
	fixturePath := filepath.Join(root, "conanfile.txt")

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), listFiles(t, root))
	if err != nil {
		t.Fatalf("Detect() unexpected error: %v", err)
	}

	byName := make(map[string]detector.Dependency, len(deps))
	for _, dep := range deps {
		byName[dep.Name] = dep
	}

	tests := []struct {
		name    string
		version string
	}{
		{"openssl", "1.1.1"},
		{"boost", "1.74.0"}, // @conan/stable suffix must be stripped
		{"zlib", "1.2.11"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dep, ok := byName[tc.name]
			if !ok {
				t.Fatalf("dependency %q not found; got keys: %v", tc.name, keys(byName))
			}
			if dep.Version != tc.version {
				t.Errorf("Version = %q, want %q", dep.Version, tc.version)
			}
			if !containsStr(dep.Evidence, fixturePath) {
				t.Errorf("Evidence missing fixture path %q; got %v", fixturePath, dep.Evidence)
			}
			if len(dep.Sources) == 0 || dep.Sources[0] != "conan" {
				t.Errorf("Sources = %v, want [conan]", dep.Sources)
			}
			wantPURL := detector.BuildPURL(tc.name, tc.version)
			if dep.PackageURL != wantPURL {
				t.Errorf("PackageURL = %q, want %q", dep.PackageURL, wantPURL)
			}
		})
	}
}

// TestConanDetector_Detect_ChannelStripped re-asserts the @user/channel strip
// explicitly, since it is a named requirement in the spec.
func TestConanDetector_Detect_ChannelStripped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "conanfile.txt")
	writeFile(t, f, "[requires]\nboost/1.74.0@conan/stable\n")

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Version != "1.74.0" {
		t.Errorf("Version = %q, want %q", deps[0].Version, "1.74.0")
	}
}

// TestConanDetector_Detect_LinesOutsideRequiresIgnored ensures that entries
// under other sections (e.g. [options]) are not treated as dependencies.
func TestConanDetector_Detect_LinesOutsideRequiresIgnored(t *testing.T) {
	f := filepath.Join(t.TempDir(), "conanfile.txt")
	content := `[generators]
cmake

[options]
boost:shared=True
openssl/1.1.1

[requires]
zlib/1.2.11
`
	writeFile(t, f, content)

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected exactly 1 dep (zlib), got %d: %v", len(deps), deps)
	}
	if deps[0].Name != "zlib" {
		t.Errorf("Name = %q, want %q", deps[0].Name, "zlib")
	}
}

// TestConanDetector_Detect_CommentsAndBlanksSkipped confirms that comment lines
// and blank lines inside [requires] do not produce dependencies.
func TestConanDetector_Detect_CommentsAndBlanksSkipped(t *testing.T) {
	f := filepath.Join(t.TempDir(), "conanfile.txt")
	content := `[requires]
# this is a comment
openssl/1.1.1

# another comment
zlib/1.2.11
`
	writeFile(t, f, content)

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %v", len(deps), deps)
	}
}

// TestConanDetector_Detect_EmptyFilesReturnsEmpty verifies that an empty file
// list produces zero deps and no error.  The non-existent-root error contract
// now belongs to the walker (cmd/root.go), not the detector.
func TestConanDetector_Detect_EmptyFilesReturnsEmpty(t *testing.T) {
	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), []string{})
	if err != nil {
		t.Fatalf("Detect() error on empty list: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for empty file list, got %d", len(deps))
	}
}

// TestConanDetector_Detect_IgnoresNonConanFiles ensures files with similar
// names are not processed.
func TestConanDetector_Detect_IgnoresNonConanFiles(t *testing.T) {
	f := filepath.Join(t.TempDir(), "conanfile.py")
	writeFile(t, f, "[requires]\nopenssl/1.1.1\n")

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), []string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for .py file, got %d", len(deps))
	}
}

// ── helper ────────────────────────────────────────────────────────────────────

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

// TestConanDetector_Detect_WritesWarningToW verifies that when a conanfile.txt
// cannot be opened, the warning is written to the W field and Detect still
// returns nil (iteration continues over remaining files).
func TestConanDetector_Detect_WritesWarningToW(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 does not reliably prevent reads on Windows")
	}

	unreadable := filepath.Join(t.TempDir(), "conanfile.txt")
	writeFile(t, unreadable, "[requires]\nopenssl/1.1.1\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o644) })

	var buf strings.Builder
	d := detector.ConanDetector{}
	d.W = &buf
	deps, detectErr := d.Detect(context.Background(), []string{unreadable})

	if detectErr != nil {
		t.Errorf("Detect() returned error %v, want nil", detectErr)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}

	captured := buf.String()
	if !strings.Contains(captured, "conan detector: skipping") {
		t.Errorf("warning output = %q, want it to contain %q", captured, "conan detector: skipping")
	}
	if !strings.Contains(captured, unreadable) {
		t.Errorf("warning output = %q, want it to contain path %q", captured, unreadable)
	}
}