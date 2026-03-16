package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// VcpkgDetector detects dependencies declared in vcpkg.json manifest files.
type VcpkgDetector struct{}

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
// It walks root for files named exactly "vcpkg.json", parses each as JSON, and
// returns one Dependency per entry in the "dependencies" array.
// Malformed JSON files are skipped with a warning written to stderr; they do
// not cause an error to be returned.
func (v VcpkgDetector) Detect(ctx context.Context, root string) ([]Dependency, error) {
	var deps []Dependency

	err := walkDir(ctx, root, func(path string, d fs.DirEntry) error {
		if d.IsDir() || d.Name() != "vcpkg.json" {
			return nil
		}

		found, parseErr := parseVcpkgFile(path)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "vcpkg detector: skipping %s: %v\n", path, parseErr)
			return nil // skip malformed files silently
		}

		deps = append(deps, found...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return deps, nil
}

// parseVcpkgFile decodes a single vcpkg.json and returns its dependencies.
func parseVcpkgFile(path string) ([]Dependency, error) {
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
			fmt.Fprintf(os.Stderr, "vcpkg detector: skipping entry in %s: %v\n", path, err)
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