package detector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"cpp-sbom-builder/internal/stdlib"
)

// includeRe matches both angle-bracket and quoted #include directives.
// Group 1 captures the opening delimiter (< or "), group 2 the header path.
var includeRe = regexp.MustCompile(`^\s*#\s*include\s*([<"])([^>"]+)[>"]`)

// cppExtensions is the set of file extensions the include scanner processes.
var cppExtensions = map[string]bool{
	".cpp": true,
	".cc":  true,
	".cxx": true,
	".h":   true,
	".hpp": true,
	".hxx": true,
}

// IncludeScanner detects third-party dependencies by scanning #include
// directives in C++ source and header files.
//
// W is the writer used for per-file warning messages (unreadable files).
// If W is nil, warnings are written to os.Stderr.
type IncludeScanner struct {
	W io.Writer
}

// Name implements Detector.
func (s IncludeScanner) Name() string { return "include" }

// Match implements Detector.
// It returns true for files whose lowercased extension is in cppExtensions.
func (s IncludeScanner) Match(path string) bool {
	return cppExtensions[strings.ToLower(filepath.Ext(path))]
}

// fileResult carries per-file scan output back to the collector goroutine.
type fileResult struct {
	path  string
	names []string // deduplicated third-party dep names found in this file
}

// Detect implements Detector.
// It filters files for C++ source and header extensions, then fans out
// scanning across a worker pool of GOMAXPROCS goroutines, merging results
// into one Dependency per unique name.
func (s IncludeScanner) Detect(ctx context.Context, files []string) ([]Dependency, error) {
	// Filter to C++ source and header files only.
	var candidates []string
	for _, path := range files {
		if s.Match(path) {
			candidates = append(candidates, path)
		}
	}

	return s.scanFiles(ctx, candidates, warnWriter(s.W)), nil
}

// scanFiles fans the given file list across a worker pool and merges results.
func (s IncludeScanner) scanFiles(ctx context.Context, files []string, w io.Writer) []Dependency {
	if len(files) == 0 {
		return nil
	}

	// Worker pool: buffered work channel + WaitGroup.
	numWorkers := runtime.GOMAXPROCS(0)
	work := make(chan string, len(files))
	for _, f := range files {
		work <- f
	}
	close(work)

	results := make(chan fileResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range work {
				// Check for cancellation before processing each file.
				select {
				case <-ctx.Done():
					return
				default:
				}
				names := scanFileIncludes(path, w)
				if len(names) > 0 {
					results <- fileResult{path: path, names: names}
				}
			}
		}()
	}

	// Close results once all workers are done.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Merge: map[depName]→Dependency, accumulating evidence paths.
	merged := map[string]*Dependency{}
	for r := range results {
		for _, name := range r.names {
			if dep, ok := merged[name]; ok {
				if !slices.Contains(dep.Evidence, r.path) {
					dep.Evidence = append(dep.Evidence, r.path)
				}
			} else {
				d := NewDependency(name, "unknown", "include", r.path)
				merged[name] = &d
			}
		}
	}

	deps := make([]Dependency, 0, len(merged))
	for _, dep := range merged {
		deps = append(deps, *dep)
	}
	return deps
}

// scanFileIncludes opens a single source file, extracts #include headers,
// filters stdlib/internal paths, and returns deduplicated third-party dep names.
// If the file cannot be opened, a warning is written to w and nil is returned.
func scanFileIncludes(path string, w io.Writer) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(w, "include scanner: skipping %s: %v\n", path, err)
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var names []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := includeRe.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		delimiter := m[1] // "<" or "\""
		header := m[2]

		// Quoted includes (#include "...") are project-local by convention.
		// Skip them unless they are flat names (no path separator), which some
		// projects use for installed third-party headers.
		if delimiter == "\"" && strings.ContainsAny(header, "/\\") {
			continue
		}

		// Skip explicit relative paths.
		if strings.HasPrefix(header, "./") || strings.HasPrefix(header, "../") {
			continue
		}

		// Skip known stdlib / POSIX headers (checks bare name and path).
		if stdlib.IsStdlib(header) {
			continue
		}

		name := DepNameFromHeader(header)
		if name == "" {
			continue
		}

		// Skip if stdlib lookup matches the resolved name (e.g. bare "vector").
		if stdlib.IsStdlib(name) {
			continue
		}

		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}

	return names
}

// DepNameFromHeader derives a dependency name from a header path.
//
//	"openssl/ssl.h"          → "openssl"   (top-level directory)
//	"boost/filesystem/path.hpp" → "boost"  (deeply nested — only first component)
//	"mylib.h"                → "mylib"     (flat header, strip extension)
//	"mylib"                  → "mylib"     (flat header, no extension)
//
// Path separators are normalised to forward-slashes before processing, so
// Windows-style paths (e.g. "openssl\ssl.h") are handled correctly.
func DepNameFromHeader(header string) string {
	// Normalise path separators (Windows tolerance).
	header = filepath.ToSlash(header)

	if idx := strings.IndexByte(header, '/'); idx > 0 {
		return strings.ToLower(header[:idx])
	}

	// Flat header — strip the extension.
	base := filepath.Base(header)
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	return strings.ToLower(base)
}