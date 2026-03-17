package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VcpkgDetector detects dependencies declared in vcpkg.json manifest files.
//
// W is the writer used for per-file warning messages (unreadable, malformed
// JSON, or malformed dependency entries).  If W is nil, warnings are written
// to os.Stderr.
type VcpkgDetector struct {
	W io.Writer
}

// Name implements Detector.
func (v VcpkgDetector) Name() string { return "vcpkg" }

// vcpkgManifest is the subset of vcpkg.json we care about.
// The "dependencies" array may hold either plain strings or objects, so each
// element is decoded into a raw json.RawMessage and handled separately.
type vcpkgManifest struct {
	Dependencies []json.RawMessage `json:"dependencies"`
}

// vcpkgDepObject represents the object form: {"name": "...", "version": "..."}.
type vcpkgDepObject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Detect implements Detector.
// It filters files for paths named exactly "vcpkg.json", parses each as JSON,
// and returns one Dependency per entry in the "dependencies" array.
// Malformed JSON files and malformed entries are skipped with a warning; they
// do not cause an error to be returned.
func (v VcpkgDetector) Detect(ctx context.Context, files []string) ([]Dependency, error) {
	var deps []Dependency
	w := warnWriter(v.W)

	for _, path := range files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if filepath.Base(path) != "vcpkg.json" {
			continue
		}

		found, parseErr := parseVcpkgFile(path, w)
		if parseErr != nil {
			fmt.Fprintf(w, "vcpkg detector: skipping %s: %v\n", path, parseErr)
			continue // skip malformed files silently
		}

		deps = append(deps, found...)
	}

	return deps, nil
}

// parseVcpkgFile decodes a single vcpkg.json and returns its dependencies.
// Warnings about individual malformed entries are written to w.
func parseVcpkgFile(path string, w io.Writer) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest vcpkgManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	deps := make([]Dependency, 0, len(manifest.Dependencies))

	for _, raw := range manifest.Dependencies {
		name, version, err := decodeVcpkgDep(raw)
		if err != nil {
			// Individual malformed entry — skip and continue.
			fmt.Fprintf(w, "vcpkg detector: skipping entry in %s: %v\n", path, err)
			continue
		}

		deps = append(deps, Dependency{
			Name:       strings.ToLower(name),
			Version:    version,
			Sources:    []string{"vcpkg"},
			Evidence:   []string{path},
			PackageURL: BuildPURL(strings.ToLower(name), version),
		})
	}

	return deps, nil
}

// decodeVcpkgDep handles both the plain-string and object forms of a vcpkg
// dependency entry.
func decodeVcpkgDep(raw json.RawMessage) (name, version string, err error) {
	// Try string form first: "openssl"
	if err = json.Unmarshal(raw, &name); err == nil {
		return name, "unknown", nil
	}

	// Try object form: {"name": "openssl", "version": "1.1.1"}
	var obj vcpkgDepObject
	if err = json.Unmarshal(raw, &obj); err != nil {
		return "", "", fmt.Errorf("dependency entry is neither a string nor an object: %w", err)
	}
	if obj.Name == "" {
		return "", "", fmt.Errorf("dependency object missing required \"name\" field")
	}

	version = obj.Version
	if version == "" {
		version = "unknown"
	}
	return obj.Name, version, nil
}