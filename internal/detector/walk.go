package detector

import (
	"context"
	"io/fs"
	"path/filepath"
	"time"
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

// walkFiles iterates a pre-built flat file list and calls fn for each entry,
// using the same callback signature as walkDir.  Every entry is presented as a
// regular file (IsDir() == false); directories are never present in a
// pre-walked list.  Context cancellation is respected between entries.
//
// This is the counterpart to walkDir used when cmd/Run has already performed a
// single shared walk and distributes the result to each detector.
func walkFiles(ctx context.Context, files []string, fn walkFn) error {
	for _, path := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := fn(path, fileEntry(path)); err != nil {
			return err
		}
	}
	return nil
}

// fileEntry returns a synthetic fs.DirEntry for a plain file path.
// Only Name() and IsDir() are called by detector callbacks; the remaining
// methods satisfy the interface but are not exercised in practice.
func fileEntry(path string) fs.DirEntry {
	return plainFileEntry(filepath.Base(path))
}

// plainFileEntry implements fs.DirEntry for a regular file.
type plainFileEntry string

func (e plainFileEntry) Name() string               { return string(e) }
func (e plainFileEntry) IsDir() bool                { return false }
func (e plainFileEntry) Type() fs.FileMode          { return 0 }
func (e plainFileEntry) Info() (fs.FileInfo, error) { return plainFileInfo(e), nil }

// plainFileInfo is the minimal fs.FileInfo companion to plainFileEntry.
// Fields beyond Name are zero-valued because no detector inspects them.
type plainFileInfo string

func (i plainFileInfo) Name() string      { return string(i) }
func (i plainFileInfo) Size() int64       { return 0 }
func (i plainFileInfo) Mode() fs.FileMode { return 0 }
func (i plainFileInfo) ModTime() time.Time { return time.Time{} }
func (i plainFileInfo) IsDir() bool       { return false }
func (i plainFileInfo) Sys() any          { return nil }