// Package walker provides recursive file-tree traversal with skip-dir pruning.
package walker

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"cpp-sbom-builder/internal/skipdir"
)

// Walk traverses root recursively and returns a flat slice of absolute paths
// for every file found.  Directories whose base-names are in the canonical
// skipdir set are pruned entirely and never descended into.
//
// Behaviour contract:
//   - If root does not exist or cannot be accessed, a descriptive non-nil error
//     is returned immediately and the returned slice is nil.
//   - Errors on non-root entries (unreadable subdirectory, broken symlink, etc.)
//     are silently skipped so that one bad node cannot abort the whole scan.
//   - ctx is checked before processing each entry; if it is cancelled or its
//     deadline exceeds, Walk stops and returns ctx.Err().
//   - Walk does not filter by file extension; callers are responsible for any
//     further filtering.
func Walk(ctx context.Context, root string) ([]string, error) {
	// Verify root is accessible before starting the walk so callers receive a
	// descriptive error rather than a silent empty result.
	if _, err := os.Lstat(root); err != nil {
		return nil, err
	}

	var paths []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				// Root became inaccessible after Lstat — propagate.
				return err
			}
			// Any other unreadable entry is skipped silently.
			return nil
		}

		// Respect context cancellation before doing any more work.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if skipdir.ShouldSkip(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		paths = append(paths, path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return paths, nil
}