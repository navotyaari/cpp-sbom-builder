package detector

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ConanDetector detects dependencies declared in conanfile.txt manifests.
type ConanDetector struct{}

// Name implements Detector.
func (c ConanDetector) Name() string { return "conan" }

// Detect implements Detector.
// It walks root for files named exactly "conanfile.txt", parses the [requires]
// section of each, and returns one Dependency per entry.
func (c ConanDetector) Detect(ctx context.Context, root string) ([]Dependency, error) {
	var deps []Dependency

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() || d.Name() != "conanfile.txt" {
			return nil
		}

		found, parseErr := parseConanFile(path)
		if parseErr != nil {
			// Unreadable file — skip silently, consistent with other detectors.
			return nil
		}

		deps = append(deps, found...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return deps, nil
}

// parseConanFile reads a conanfile.txt and extracts dependencies from the
// [requires] section. It stops collecting when a new section header is found.
func parseConanFile(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	inRequires := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Blank lines and comments are always skipped.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Section header detection.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inRequires = line == "[requires]"
			continue
		}

		if !inRequires {
			continue
		}

		name, version, ok := parseConanRequire(line)
		if !ok {
			continue
		}

		deps = append(deps, Dependency{
			Name:       name,
			Version:    version,
			Sources:    []string{"conan"},
			Evidence:   []string{path},
			PackageURL: BuildPURL(name, version),
		})
	}

	return deps, scanner.Err()
}

// parseConanRequire parses a single [requires] line of the form:
//
//	<name>/<version>
//	<name>/<version>@<user>/<channel>
//
// Returns the normalised name, version, and true on success.
func parseConanRequire(line string) (name, version string, ok bool) {
	// Must contain a slash separating name from version.
	slashIdx := strings.IndexByte(line, '/')
	if slashIdx <= 0 {
		return "", "", false
	}

	name = strings.ToLower(strings.TrimSpace(line[:slashIdx]))

	// Everything after the first slash is "<version>[@user/channel]".
	rest := line[slashIdx+1:]

	// Strip optional @user/channel suffix.
	if atIdx := strings.IndexByte(rest, '@'); atIdx >= 0 {
		rest = rest[:atIdx]
	}

	version = strings.TrimSpace(rest)
	if name == "" || version == "" {
		return "", "", false
	}

	return name, version, true
}
