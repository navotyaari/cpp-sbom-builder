package detector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ConanDetector detects dependencies declared in conanfile.txt manifests.
//
// W is the writer used for per-file warning messages (unreadable or
// unparseable files).  If W is nil, warnings are written to os.Stderr.
type ConanDetector struct {
	W io.Writer
}

// Name implements Detector.
func (c ConanDetector) Name() string { return "conan" }

// Match implements Detector.
// It returns true for files named exactly "conanfile.txt".
func (c ConanDetector) Match(path string) bool {
	return filepath.Base(path) == "conanfile.txt"
}

// Detect implements Detector.
// It filters files for paths named exactly "conanfile.txt", parses the
// [requires] section of each, and returns one Dependency per entry.
func (c ConanDetector) Detect(ctx context.Context, files []string) ([]Dependency, error) {
	var deps []Dependency
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

		found, parseErr := parseConanFile(path)
		if parseErr != nil {
			fmt.Fprintf(w, "conan detector: skipping %s: %v\n", path, parseErr)
			continue
		}

		deps = append(deps, found...)
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

		deps = append(deps, NewDependency(name, version, "conan", path))
	}

	return deps, scanner.Err()
}

// parseConanRequire parses a single [requires] line of the form:
//
//	<n>/<version>
//	<n>/<version>@<user>/<channel>
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