package walker_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"cpp-sbom-builder/internal/skipdir"
	"cpp-sbom-builder/internal/walker"
)

// mkFile creates a file at the given path, creating parent directories as needed.
func mkFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%q): %v", path, err)
	}
	f.Close()
}

// sortedWalk calls Walk with a background context and returns the results
// sorted for deterministic comparison.
func sortedWalk(t *testing.T, root string) []string {
	t.Helper()
	paths, err := walker.Walk(context.Background(), root)
	if err != nil {
		t.Fatalf("Walk(%q) unexpected error: %v", root, err)
	}
	sort.Strings(paths)
	return paths
}

// TestWalk_ValidFilesReturned verifies that files in non-filtered directories
// are present in the results.
func TestWalk_ValidFilesReturned(t *testing.T) {
	root := t.TempDir()

	want := []string{
		filepath.Join(root, "main.cpp"),
		filepath.Join(root, "src", "util.cpp"),
		filepath.Join(root, "include", "util.h"),
	}

	for _, p := range want {
		mkFile(t, p)
	}

	got := sortedWalk(t, root)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("got %d paths, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestWalk_SkippedDirsExcluded verifies that none of the skip-listed directory
// names appear anywhere in the returned paths.
func TestWalk_SkippedDirsExcluded(t *testing.T) {
	root := t.TempDir()

	// Files that MUST appear.
	mkFile(t, filepath.Join(root, "CMakeLists.txt"))
	mkFile(t, filepath.Join(root, "src", "app.cpp"))

	// Files inside filtered directories that MUST NOT appear.
	filtered := []string{
		filepath.Join(root, ".git", "config"),
		filepath.Join(root, "build", "app.o"),
		filepath.Join(root, "cmake-build-debug", "app"),
		filepath.Join(root, "cmake-build-release", "app"),
		filepath.Join(root, "node_modules", "lodash", "index.js"),
		filepath.Join(root, ".cache", "clangd", "index.bin"),
	}
	for _, p := range filtered {
		mkFile(t, p)
	}

	got := sortedWalk(t, root)

	// Build a set for quick lookup.
	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		gotSet[p] = true
	}

	for _, p := range filtered {
		if gotSet[p] {
			t.Errorf("filtered file should not appear in results: %q", p)
		}
	}

	// Sanity-check that the visible files do appear.
	for _, p := range []string{
		filepath.Join(root, "CMakeLists.txt"),
		filepath.Join(root, "src", "app.cpp"),
	} {
		if !gotSet[p] {
			t.Errorf("expected file missing from results: %q", p)
		}
	}
}

// TestWalk_NonExistentRootReturnsError verifies that Walk returns a non-nil
// error when the root path does not exist.
func TestWalk_NonExistentRootReturnsError(t *testing.T) {
	_, err := walker.Walk(context.Background(), "/this/path/does/not/exist/at/all")
	if err == nil {
		t.Fatal("expected an error for a non-existent root, got nil")
	}
}

// TestWalk_EmptyDirectoryReturnsEmptySlice verifies that an empty root
// directory yields an empty (non-nil-error) result.
func TestWalk_EmptyDirectoryReturnsEmptySlice(t *testing.T) {
	root := t.TempDir()
	paths, err := walker.Walk(context.Background(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 paths for empty dir, got %d: %v", len(paths), paths)
	}
}

// TestWalk_NestedFilteredDirSkipped verifies that a skip-listed directory
// nested deeper in the tree is also pruned.
func TestWalk_NestedFilteredDirSkipped(t *testing.T) {
	root := t.TempDir()

	mkFile(t, filepath.Join(root, "lib", "core.cpp"))
	mkFile(t, filepath.Join(root, "lib", "build", "core.o")) // nested "build" dir

	got := sortedWalk(t, root)

	// hasSkippedComponent returns true if any path component of p is a name
	// that the canonical skipdir set requires to be pruned.
	hasSkippedComponent := func(p string) bool {
		for p != "" {
			dir, base := filepath.Split(filepath.Clean(p))
			if skipdir.ShouldSkip(base) {
				return true
			}
			// filepath.Split on a root like "/" returns ("", "/") — stop when
			// we can no longer make progress.
			if dir == p {
				break
			}
			p = filepath.Clean(dir)
		}
		return false
	}

	for _, p := range got {
		if hasSkippedComponent(p) {
			t.Errorf("file inside nested filtered dir should be excluded: %q", p)
		}
	}

	found := false
	for _, p := range got {
		if p == filepath.Join(root, "lib", "core.cpp") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lib/core.cpp in results, got: %v", got)
	}
}

// TestWalk_ContextCancellation verifies that Walk stops and returns a non-nil
// error when the supplied context is cancelled before or during traversal.
func TestWalk_ContextCancellation(t *testing.T) {
	root := t.TempDir()

	// Populate enough files that there is meaningful work for Walk to do.
	for _, name := range []string{
		"a.cpp", "b.cpp", "c.cpp",
		filepath.Join("src", "d.cpp"),
		filepath.Join("src", "e.cpp"),
		filepath.Join("include", "f.h"),
	} {
		mkFile(t, filepath.Join(root, name))
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel before the walk starts so the context is already done on entry.
	cancel()

	_, err := walker.Walk(ctx, root)
	if err == nil {
		t.Fatal("expected a non-nil error from a cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}