package detector_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/detector"
)

func TestVcpkgDetector_Name(t *testing.T) {
	d := detector.VcpkgDetector{}
	if got := d.Name(); got != "vcpkg" {
		t.Errorf("Name() = %q, want %q", got, "vcpkg")
	}
}

func TestVcpkgDetector_Detect_Fixture(t *testing.T) {
	root := fixtureDir(t, "vcpkg")
	fixturePath := filepath.Join(root, "vcpkg.json")

	d := detector.VcpkgDetector{}
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
		{"zlib", "unknown"},    // plain string entry
		{"openssl", "1.1.1"},   // object with version
		{"fmt", "unknown"},     // object without version
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
				t.Errorf("Evidence does not contain %q; got %v", fixturePath, dep.Evidence)
			}
			if len(dep.Sources) == 0 || dep.Sources[0] != "vcpkg" {
				t.Errorf("Sources = %v, want [vcpkg]", dep.Sources)
			}
			wantPURL := detector.BuildPURL(tc.name, tc.version)
			if dep.PackageURL != wantPURL {
				t.Errorf("PackageURL = %q, want %q", dep.PackageURL, wantPURL)
			}
		})
	}
}

func TestVcpkgDetector_Detect_MalformedJSON(t *testing.T) {
	root := t.TempDir()

	// Write a file named vcpkg.json with invalid JSON content.
	bad := filepath.Join(root, "vcpkg.json")
	if err := os.WriteFile(bad, []byte(`{ this is not valid json `), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	d := detector.VcpkgDetector{}
	deps, err := d.Detect(context.Background(), root)

	if err != nil {
		t.Errorf("Detect() returned error for malformed JSON, want nil; got: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("Detect() returned %d deps for malformed JSON, want 0; got: %v", len(deps), deps)
	}
}

func TestVcpkgDetector_Detect_IgnoresNonVcpkgFiles(t *testing.T) {
	root := t.TempDir()

	// A file that looks similar but is not named exactly "vcpkg.json".
	impostor := filepath.Join(root, "vcpkg.configuration.json")
	content := `{"dependencies": ["openssl"]}`
	if err := os.WriteFile(impostor, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	d := detector.VcpkgDetector{}
	deps, err := d.Detect(context.Background(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d: %v", len(deps), deps)
	}
}

func TestVcpkgDetector_Detect_NonExistentRoot(t *testing.T) {
	d := detector.VcpkgDetector{}
	_, err := d.Detect(context.Background(), "/no/such/path/vcpkg")
	if err == nil {
		t.Fatal("expected error for non-existent root, got nil")
	}
}
