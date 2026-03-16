package detector

import (
	"context"
	"io/fs"
	"path/filepath"
)

// walkFn is the per-entry callback supplied by each detector.
// It receives the absolute path and the directory entry for every non-root
// node that WalkDir visits.  Returning a non-nil error aborts the walk and
// that error is propagated by walkDir.
type walkFn func(path string, d fs.DirEntry) error

// walkDir walks the tree rooted at root, applying the shared error-handling
// policy used by every detector:
//
//   - An error on the root entry itself is fatal and returned immediately.
//   - Errors on any other entry (unreadable directory, broken symlink, etc.)
//     are silently skipped so that one bad node cannot abort the whole scan.
//   - Context cancellation is checked before each entry is handed to fn.
//
// fn is called for every successfully visited entry (files and directories
// alike); it is fn's responsibility to skip directories or irrelevant files.
func walkDir(ctx context.Context, root string, fn walkFn) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err // root inaccessible — propagate
			}
			return nil // non-root error — skip silently
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		return fn(path, d)
	})
}