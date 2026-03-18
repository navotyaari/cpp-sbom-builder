package detector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// findPackageRe matches find_package(...) calls and captures:
//
//	group 1 – package name
//	group 2 – optional version number (first token after the name if it looks
//	           like a version, i.e. starts with a digit)
var findPackageRe = regexp.MustCompile(
	`(?i)find_package\s*\(\s*(\w+)(?:\s+(\d[\d.]*))?`,
)

// cmakePseudoPackages is the set of lowercase names that CMake resolves
// internally and that do not represent third-party libraries. Entries in this
// set are silently skipped by parseCMakeFile so they never appear as SBOM
// components. All keys are lowercase because the detector normalises every
// extracted name with strings.ToLower before the lookup.
var cmakePseudoPackages = map[string]bool{
	"threads":                        true, // pthreads / Win32 threading — no external package identity
	"cmake":                          true, // CMake itself
	"ctest":                          true, // CMake test driver
	"cpack":                          true, // CMake packaging tool
	"packagehandlestandardargs":      true, // CMake helper module
	"cmakepackageconfighelpers":       true, // CMake helper module
	"findpackagehandlestandardargs":   true, // legacy alias for PackageHandleStandardArgs
}

// CMakeDetector detects dependencies declared via find_package() in
// CMakeLists.txt and *.cmake files.
//
// W is the writer used for per-file warning messages (unreadable files, scan
// errors).  If W is nil, warnings are written to os.Stderr.
type CMakeDetector struct {
	W io.Writer
}

// Name implements Detector.
func (c CMakeDetector) Name() string { return "cmake" }

// Match implements Detector.
// It returns true for files named CMakeLists.txt or with a .cmake extension
// (case insensitive).
func (c CMakeDetector) Match(path string) bool {
	return isCMakeFile(filepath.Base(path))
}

// Detect implements Detector.
// It filters files for CMakeLists.txt / *.cmake paths, extracts find_package()
// calls from each, and returns one Dependency per unique normalised package name.
func (c CMakeDetector) Detect(ctx context.Context, files []string) ([]Dependency, error) {
	deps := map[string]*Dependency{}
	w := warnWriter(c.W)

	for _, path := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if !c.Match(path) {
			continue
		}

		if err := parseCMakeFile(path, deps, w); err != nil {
			return nil, err
		}
	}

	result := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		result = append(result, *dep)
	}
	return result, nil
}

// isCMakeFile reports whether name is a CMake source file.
func isCMakeFile(name string) bool {
	return name == "CMakeLists.txt" || strings.EqualFold(filepath.Ext(name), ".cmake")
}

// parseCMakeFile scans a single file and upserts entries into deps.
// Warnings about unreadable files or scan errors are written to w.
func parseCMakeFile(path string, deps map[string]*Dependency, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(w, "cmake detector: skipping %s: %v\n", path, err)
		return nil // unreadable file → skip silently
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		m := findPackageRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		name := strings.ToLower(m[1])
		version := "unknown"
		if m[2] != "" {
			version = m[2]
		}

		// Skip CMake built-in modules that have no third-party package identity.
		if cmakePseudoPackages[name] {
			continue
		}

		if existing, ok := deps[name]; ok {
			// Already seen from another file — add evidence path if new.
			if !slices.Contains(existing.Evidence, path) {
				existing.Evidence = append(existing.Evidence, path)
			}
			// Prefer a concrete version over "unknown".
			if existing.Version == "unknown" && version != "unknown" {
				existing.Version = version
				existing.PackageURL = BuildPURL(name, version)
			}
		} else {
			d := NewDependency(name, version, "cmake", path)
			deps[name] = &d
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(w, "cmake detector: skipping %s: %v\n", path, err)
	}
	return nil
}