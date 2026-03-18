// Package detector defines the shared types and interface that all dependency
// detectors must implement.
package detector

import (
	"context"
	"fmt"
)

// Dependency represents a single third-party dependency discovered during scanning.
type Dependency struct {
	// Name is the canonical package name (e.g. "boost", "openssl").
	Name string

	// Version is the resolved version string, or empty if unknown.
	Version string

	// Sources lists the detector names that identified this dependency
	// (e.g. "cmake", "vcpkg"). A dependency found by multiple detectors will
	// have more than one entry here after merging.
	Sources []string

	// Evidence holds the file paths that triggered detection (e.g. the path to
	// the CMakeLists.txt or vcpkg.json that referenced this package).
	Evidence []string

	// PackageURL is the package URL in purl format: pkg:generic/<n>@<version>.
	// Use BuildPURL to construct this value.
	PackageURL string
}

// Detector is the interface that every dependency detector must satisfy.
//
// Detect receives a pre-built, skip-dir-pruned flat file list produced by the
// shared walker in cmd/root.go.  Each detector filters that list for the paths
// it cares about and reads those files directly; it never walks the filesystem
// itself.  Detect must honour context cancellation and must not modify any files.
type Detector interface {
	// Name returns a short, stable identifier for the detector (e.g. "cmake").
	Name() string

	// Match reports whether the file at path is relevant to this detector.
	// The fan-out in cmd/root.go calls Match before routing each file, so
	// Detect can assume every file it receives has already passed Match.
	//
	// Convention: Match must be a fast check (filename or extension
	// comparison) since it is called once per file per detector in the
	// fan-out critical path.
	Match(path string) bool

	// Detect scans the provided file list and returns all dependencies it can
	// identify.  files contains absolute paths; the caller guarantees that
	// skip-listed directories have already been pruned.
	Detect(ctx context.Context, files []string) ([]Dependency, error)
}

// NewDependency constructs a Dependency with all required fields populated.
// PackageURL is always set via BuildPURL, ensuring it is never empty or malformed.
func NewDependency(name, version, source, evidence string) Dependency {
	return Dependency{
		Name:       name,
		Version:    version,
		Sources:    []string{source},
		Evidence:   []string{evidence},
		PackageURL: BuildPURL(name, version),
	}
}

// BuildPURL constructs a Package URL in the format pkg:generic/<n>@<version>.
// If version is empty the "@<version>" suffix is omitted.
func BuildPURL(name, version string) string {
	if version == "" {
		return fmt.Sprintf("pkg:generic/%s", name)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", name, version)
}