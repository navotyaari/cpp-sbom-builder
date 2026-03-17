package detector

import (
	"bufio"
	"context"
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
type IncludeScanner struct{}

// Name implements Detector.
func (s IncludeScanner) Name() string { return "include" }

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
		if cppExtensions[strings.ToLower(filepath.Ext(path))] {
			candidates = append(candidates, path)
		}
	}

	return s.scanFiles(ctx, candidates), nil
}

// scanFiles fans the given file list across a worker pool and merges results.
func (s IncludeScanner) scanFiles(ctx context.Context, files []string) []Dependency {
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
				names := scanFileIncludes(path)
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
				merged[name] = &Dependency{
					Name:       name,
					Version:    "unknown",
					Sources:    []string{"include"},
					Evidence:   []string{r.path},
					PackageURL: BuildPURL(name, "unknown"),
				}
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
func scanFileIncludes(path string) []string {
	f, err := os.Open(path)
	if err != nil {
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

		name := depNameFromHeader(header)
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

// depNameFromHeader derives a dependency name from a header path.
//
//	"openssl/ssl.h"   → "openssl"   (top-level directory)
//	"boost/regex.hpp" → "boost"
//	"mylib.h"         → "mylib"     (flat header, strip extension)
func depNameFromHeader(header string) string {
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