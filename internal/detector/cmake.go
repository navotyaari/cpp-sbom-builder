package detector

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
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

// CMakeDetector detects dependencies declared via find_package() in
// CMakeLists.txt and *.cmake files.
type CMakeDetector struct{}

// Name implements Detector.
func (c CMakeDetector) Name() string { return "cmake" }

// Detect implements Detector.
// It walks root for CMakeLists.txt / *.cmake files, extracts find_package()
// calls, and returns one Dependency per unique normalised package name.
func (c CMakeDetector) Detect(ctx context.Context, root string) ([]Dependency, error) {
	deps := map[string]*Dependency{}

	err := walkDir(ctx, root, cmakeCallback(deps))
	if err != nil {
		return nil, err
	}

	return cmakeDepsToSlice(deps), nil
}

// DetectFiles implements FilesDetector.
// It applies the same logic as Detect but operates on a pre-built file list
// rather than walking the filesystem independently.
func (c CMakeDetector) DetectFiles(ctx context.Context, files []string) ([]Dependency, error) {
	deps := map[string]*Dependency{}

	err := walkFiles(ctx, files, cmakeCallback(deps))
	if err != nil {
		return nil, err
	}

	return cmakeDepsToSlice(deps), nil
}

// cmakeCallback returns the walkFn shared by both Detect and DetectFiles.
func cmakeCallback(deps map[string]*Dependency) walkFn {
	return func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			return nil
		}

		if !isCMakeFile(d.Name()) {
			return nil
		}

		return parseCMakeFile(path, deps)
	}
}

// cmakeDepsToSlice converts the accumulator map to a flat slice.
func cmakeDepsToSlice(deps map[string]*Dependency) []Dependency {
	result := make([]Dependency, 0, len(deps))
	for _, dep := range deps {
		result = append(result, *dep)
	}
	return result
}

// isCMakeFile reports whether name is a CMake source file.
func isCMakeFile(name string) bool {
	return name == "CMakeLists.txt" || strings.EqualFold(filepath.Ext(name), ".cmake")
}

// parseCMakeFile scans a single file and upserts entries into deps.
func parseCMakeFile(path string, deps map[string]*Dependency) error {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cmake detector: skipping %s: %v\n", path, err)
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
			if !slices.Contains(existing.Evidence, path) {
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

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "cmake detector: skipping %s: %v\n", path, err)
	}
	return nil
}