// Package stdlib provides a static allowlist of C++ standard library, C, and
// POSIX system headers so that detectors can filter them out before reporting
// third-party dependencies.
package stdlib

import "strings"

// stdlibHeaders is the canonical set of headers considered internal / system-level.
// Keys are bare header names with no angle brackets.
var stdlibHeaders = map[string]bool{
	// ── C++ Standard Library ─────────────────────────────────────────────────
	"algorithm":     true,
	"any":           true,
	"array":         true,
	"bitset":        true,
	"chrono":        true,
	"deque":         true,
	"filesystem":    true,
	"fstream":       true,
	"functional":    true,
	"iostream":      true,
	"istream":       true,
	"iterator":      true,
	"list":          true,
	"map":           true,
	"memory":        true,
	"mutex":         true,
	"numeric":       true,
	"optional":      true,
	"ostream":       true,
	"queue":         true,
	"random":        true,
	"regex":         true,
	"set":           true,
	"sstream":       true,
	"stack":         true,
	"stdexcept":     true,
	"string":        true,
	"thread":        true,
	"tuple":         true,
	"type_traits":   true,
	"typeinfo":      true,
	"unordered_map": true,
	"unordered_set": true,
	"utility":       true,
	"variant":       true,
	"vector":        true,

	// ── C Standard Headers ───────────────────────────────────────────────────
	"assert.h":  true,
	"ctype.h":   true,
	"errno.h":   true,
	"float.h":   true,
	"limits.h":  true,
	"math.h":    true,
	"stdbool.h": true,
	"stddef.h":  true,
	"stdint.h":  true,
	"stdio.h":   true,
	"stdlib.h":  true,
	"string.h":  true,
	"time.h":    true,

	// ── POSIX / System Headers ───────────────────────────────────────────────
	"arpa/inet.h":   true,
	"dirent.h":      true,
	"dlfcn.h":       true,
	"fcntl.h":       true,
	"netinet/in.h":  true,
	"pthread.h":     true,
	"signal.h":      true,
	"sys/socket.h":  true,
	"sys/stat.h":    true,
	"sys/types.h":   true,
	"unistd.h":      true,
}

// normalize strips surrounding angle brackets from a header name.
// "<vector>" becomes "vector"; "vector" is returned unchanged.
func normalize(header string) string {
	return strings.TrimSuffix(strings.TrimPrefix(header, "<"), ">")
}

// IsStdlib reports whether header is a known C++ standard library, C, or
// POSIX/system header. Surrounding angle brackets are stripped before lookup,
// so both "vector" and "<vector>" return true.
func IsStdlib(header string) bool {
	return stdlibHeaders[normalize(header)]
}
