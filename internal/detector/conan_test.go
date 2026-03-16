package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

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
	deps, err := d.Detect(context.Background(), root)
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
		{"boost", "1.74.0"},  // @conan/stable suffix must be stripped
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
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "conanfile.txt"), "[requires]\nboost/1.74.0@conan/stable\n")

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), root)
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
	root := t.TempDir()
	content := `[generators]
cmake

[options]
boost:shared=True
openssl/1.1.1

[requires]
zlib/1.2.11
`
	writeFile(t, filepath.Join(root, "conanfile.txt"), content)

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), root)
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
	root := t.TempDir()
	content := `[requires]
# this is a comment
openssl/1.1.1

# another comment
zlib/1.2.11
`
	writeFile(t, filepath.Join(root, "conanfile.txt"), content)

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %v", len(deps), deps)
	}
}

// TestConanDetector_Detect_NonExistentRoot verifies the error contract.
func TestConanDetector_Detect_NonExistentRoot(t *testing.T) {
	d := detector.ConanDetector{}
	_, err := d.Detect(context.Background(), "/no/such/path/conan")
	if err == nil {
		t.Fatal("expected error for non-existent root, got nil")
	}
}

// TestConanDetector_Detect_IgnoresNonConanFiles ensures files with similar
// names are not processed.
func TestConanDetector_Detect_IgnoresNonConanFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "conanfile.py"), "[requires]\nopenssl/1.1.1\n")

	d := detector.ConanDetector{}
	deps, err := d.Detect(context.Background(), root)
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
