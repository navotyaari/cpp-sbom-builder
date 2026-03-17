// Package walker provides recursive file-tree traversal with skip-dir pruning.
package walker

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"cpp-sbom-builder/internal/skipdir"
)

// walkBufSize is the number of file paths that can be buffered in the channel
// returned by Walk. A buffer of 64 lets the walker goroutine stay up to 64
// entries ahead of its consumers on fast storage without holding the entire
// file list in memory. The value is intentionally modest — the goal is to
// smooth out short bursts of consumer slowness, not to pre-load the tree.
const walkBufSize = 64

// Walk traverses root recursively and streams absolute file paths into the
// returned channel.  Directories whose base-names are in the canonical skipdir
// set are pruned entirely and never descended into.  The channel is closed by
// the walker goroutine when traversal is complete or when it is stopped by
// context cancellation.
//
// Behaviour contract:
//   - If root does not exist or cannot be accessed, a non-nil error is returned
//     immediately and the returned channel is nil.
//   - Errors on non-root entries (unreadable subdirectory, broken symlink, etc.)
//     are silently skipped so that one bad node cannot abort the whole scan.
//   - ctx is checked before processing each entry; if it is cancelled the
//     walker stops and closes the channel.  Callers should check ctx.Err()
//     after the channel is drained to determine whether traversal was cut short.
//   - Walk does not filter by file extension; callers are responsible for any
//     further filtering.
//   - The caller must drain the returned channel to completion; not doing so
//     will leave the walker goroutine blocked.
func Walk(ctx context.Context, root string) (chan string, error) {
	// Verify root is accessible before starting the goroutine so callers
	// receive a descriptive error rather than a silently closed channel.
	if _, err := os.Lstat(root); err != nil {
		return nil, err
	}

	ch := make(chan string, walkBufSize)

	go func() {
		defer close(ch)

		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error { //nolint:errcheck
			if err != nil {
				if path == root {
					// Root became inaccessible after Lstat — stop the walk.
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

			// Send path to consumers, but also respect cancellation so we
			// don't block forever if a consumer has stopped reading.
			select {
			case ch <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}()

	return ch, nil
}