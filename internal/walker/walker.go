// Package walker provides recursive file-tree traversal for C++ source files.
package walker

import (
	"io/fs"
	"os"
	"path/filepath"
)

// skipDirs is the set of directory names that should never be descended into.
var skipDirs = map[string]bool{
	".git":                true,
	"build":               true,
	"cmake-build-debug":   true,
	"cmake-build-release": true,
	"node_modules":        true,
	".cache":              true,
}

// Walk traverses root recursively and returns a flat slice of every file path
// encountered. Directories listed in skipDirs are pruned entirely. If root
// itself cannot be opened, a non-nil error is returned. Errors encountered
// while reading subdirectories or individual files are silently ignored.
func Walk(root string) ([]string, error) {
	// Verify root is accessible before starting the walk.
	if _, err := os.Lstat(root); err != nil {
		return nil, err
	}

	var paths []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// root itself failed — propagate so the caller knows the walk is broken.
			if path == root {
				return err
			}
			// Any other unreadable entry is skipped silently.
			return nil
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
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
