// Package skipdir defines the canonical set of directory names that the walker
// must prune during filesystem traversal.
//
// Having a single source of truth here means every consumer — the walker,
// tests, and future tooling — stays in sync automatically.
package skipdir

// Dirs is the set of directory names that should never be descended into
// during a project scan.  Keys are exact directory base-names (not paths).
//
// The set covers:
//   - Version-control metadata (.git)
//   - Compiled-output trees (build, cmake-build-debug, cmake-build-release)
//   - Third-party package trees that are not part of the project source
//     (node_modules)
//   - Tool caches that contain no source or manifest files (.cache)
var Dirs = map[string]bool{
	".git":                true,
	"build":               true,
	"cmake-build-debug":   true,
	"cmake-build-release": true,
	"node_modules":        true,
	".cache":              true,
}

// ShouldSkip reports whether name is a directory that the walker must prune.
// name must be a bare directory base-name, not a full path.
func ShouldSkip(name string) bool {
	return Dirs[name]
}