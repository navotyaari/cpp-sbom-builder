package detector

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// findPackageRe matches find_package(...) calls and captures:
//   group 1 – package name
//   group 2 – optional version number (first token after the name if it looks
//              like a version, i.e. starts with a digit)
var findPackageRe = regexp.MustCompile(
	`(?i)find_package\s*\(\s*(\w+)(?:\s+(\d[\d.]*))?`,
)

// CMakeDetector detects dependencies declared via find_package() in
// CMakeLists.txt and *.cmake files.
type CMakeDetector struct{}

// Name implements Detector.
func (c CMakeDetector) Name() string { return "cmake" }

// Detect implements Detector.
// It walks root for CMakeLists.txt / *.cmake files, extracts find_package()
// calls, and returns one Dependency per unique normalised package name.
func (c CMakeDetector) Detect(ctx context.Context, root string) ([]Dependency, error) {
	// deps accumulates results keyed by normalised name so duplicates
	// (same package in multiple files) are merged into one entry.
	deps := map[string]*Dependency{}

	err := walkDir(ctx, root, func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			return nil
		}

		if !isCMakeFile(d.Name()) {
			return nil
		}

		return parseCMakeFile(path, deps)
	})

	if err != nil {
		return nil, err
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
func parseCMakeFile(path string, deps map[string]*Dependency) error {
	f, err := os.Open(path)
	if err != nil {
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

		if existing, ok := deps[name]; ok {
			// Already seen from another file — add evidence path if new.
			if !containsString(existing.Evidence, path) {
				existing.Evidence = append(existing.Evidence, path)
			}
			// Prefer a concrete version over "unknown".
			if existing.Version == "unknown" && version != "unknown" {
				existing.Version = version
				existing.PackageURL = BuildPURL(name, version)
			}
		} else {
			deps[name] = &Dependency{
				Name:       name,
				Version:    version,
				Sources:    []string{"cmake"},
				Evidence:   []string{path},
				PackageURL: BuildPURL(name, version),
			}
		}
	}

	return scanner.Err()
}

// containsString reports whether slice contains s.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}