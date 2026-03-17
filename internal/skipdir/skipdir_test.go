package skipdir_test

import (
	"testing"

	"cpp-sbom-builder/internal/skipdir"
)

// requiredDirs lists every directory name that the specification mandates must
// be present in the skip set.  Add new entries here when the spec changes.
var requiredDirs = []string{
	".git",
	"build",
	"cmake-build-debug",
	"cmake-build-release",
	"node_modules",
	".cache",
}

// TestDirs_ContainsRequiredNames verifies that the canonical Dirs map includes
// every directory name required by the specification.
func TestDirs_ContainsRequiredNames(t *testing.T) {
	for _, name := range requiredDirs {
		if !skipdir.Dirs[name] {
			t.Errorf("skipdir.Dirs is missing required entry %q", name)
		}
	}
}

// TestShouldSkip_ReturnsTrueForSkippedDirs verifies that ShouldSkip returns
// true for every name that must be pruned.
func TestShouldSkip_ReturnsTrueForSkippedDirs(t *testing.T) {
	for _, name := range requiredDirs {
		if !skipdir.ShouldSkip(name) {
			t.Errorf("ShouldSkip(%q) = false, want true", name)
		}
	}
}

// TestShouldSkip_ReturnsFalseForNormalDirs verifies that ShouldSkip does not
// accidentally prune directories that should be traversed.
func TestShouldSkip_ReturnsFalseForNormalDirs(t *testing.T) {
	normalDirs := []string{
		"src",
		"include",
		"lib",
		"test",
		"docs",
		"cmake",
		"third_party",
		"",
	}
	for _, name := range normalDirs {
		if skipdir.ShouldSkip(name) {
			t.Errorf("ShouldSkip(%q) = true, want false", name)
		}
	}
}