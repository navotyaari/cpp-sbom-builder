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
type Detector interface {
	// Name returns a short, stable identifier for the detector (e.g. "cmake").
	Name() string
 
	// Detect scans the project rooted at root and returns all dependencies it
	// can identify. It should honour context cancellation. It must not modify
	// any files; it is read-only with respect to the filesystem.
	Detect(ctx context.Context, root string) ([]Dependency, error)
}
 
// BuildPURL constructs a Package URL in the format pkg:generic/<name>@<version>.
// If version is empty the "@<version>" suffix is omitted.
func BuildPURL(name, version string) string {
	if version == "" {
		return fmt.Sprintf("pkg:generic/%s", name)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", name, version)
}
 