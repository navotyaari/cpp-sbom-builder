// Package formatter serializes a merged dependency list to a CycloneDX 1.4
// JSON SBOM document.
package formatter

import (
	"fmt"
	"time"

	"cpp-sbom-builder/internal/detector"
)

// ── CycloneDX 1.4 output structs ─────────────────────────────────────────────

// SBOMReport is the top-level CycloneDX 1.4 document.
type SBOMReport struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

// Metadata holds generation metadata for the SBOM.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component Component `json:"component"`
}

// Tool describes the software that produced the SBOM.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component represents a single software component (library or application).
type Component struct {
	Type     string             `json:"type"`
	BOMRef   string             `json:"bom-ref"`
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	PURL     string             `json:"purl"`
	Evidence *ComponentEvidence `json:"evidence,omitempty"`
}

// ComponentEvidence lists the file locations where this component was observed.
type ComponentEvidence struct {
	Occurrences []Occurrence `json:"occurrences"`
}

// Occurrence is a single file path where a component was detected.
type Occurrence struct {
	Location string `json:"location"`
}

// ── Formatter ────────────────────────────────────────────────────────────────

const (
	toolVendor = "cpp-sbom-builder"
	toolName   = "cpp-sbom-builder"
)

// toolVersion is the version string embedded in the metadata.tools entry of
// every generated SBOM.  It defaults to "dev" for local builds and is
// overridden at release time via:
//
//	go build -ldflags "-X cpp-sbom-builder/internal/formatter.toolVersion=x.y.z"
var toolVersion = "dev"

// Format converts a merged dependency slice into a CycloneDX 1.4 SBOMReport.
// projectName is used as the metadata.component name.
// If deps is nil or empty, Components is an empty (non-null) JSON array.
func Format(deps []detector.Dependency, projectName string) (SBOMReport, error) {
	// seen tracks how many times each base bom-ref candidate has been used,
	// allowing us to assign a unique suffix on collision.
	// used is the set of all bom-ref values already committed to the document.
	seen := make(map[string]int)  // base candidate → count of assignments so far
	used := make(map[string]bool) // fully resolved bom-ref → already taken

	// Reserve the root metadata component's bom-ref first so that component
	// bom-refs cannot collide with it.
	rootBase := projectName + "-unknown"
	rootBOMRef := assignBOMRef(rootBase, seen, used)

	components := make([]Component, 0, len(deps)) // never nil → serialises as []
	for _, dep := range deps {
		base := dep.Name + "-" + dep.Version
		bomRef := assignBOMRef(base, seen, used)
		components = append(components, dependencyToComponent(dep, bomRef))
	}

	report := SBOMReport{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.4",
		Version:     1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{
				{
					Vendor:  toolVendor,
					Name:    toolName,
					Version: toolVersion,
				},
			},
			Component: Component{
				Type:    "application",
				BOMRef:  rootBOMRef,
				Name:    projectName,
				Version: "unknown",
				PURL:    "",
			},
		},
		Components: components,
	}

	return report, nil
}

// assignBOMRef returns a document-unique bom-ref derived from base.
//
// Rules:
//   - The first time base is seen it is returned unchanged (preserves the
//     human-readable name-version form for the common case).
//   - On each subsequent collision a numeric suffix is appended: base-2,
//     base-3, … incrementing until a free slot is found.
//
// The result is always recorded in both seen and used before returning, so
// future calls cannot produce the same value.
func assignBOMRef(base string, seen map[string]int, used map[string]bool) string {
	seen[base]++
	count := seen[base]

	var candidate string
	if count == 1 {
		candidate = base
	} else {
		candidate = fmt.Sprintf("%s-%d", base, count)
	}

	// In the unlikely event the suffixed form is itself already taken
	// (e.g. a component literally named "foo-unknown-2"), keep incrementing.
	for used[candidate] {
		count++
		candidate = fmt.Sprintf("%s-%d", base, count)
	}

	used[candidate] = true
	return candidate
}

// dependencyToComponent maps a single Dependency to its Component representation.
// bomRef must already be a document-unique value supplied by the caller.
func dependencyToComponent(dep detector.Dependency, bomRef string) Component {
	c := Component{
		Type:    "library",
		BOMRef:  bomRef,
		Name:    dep.Name,
		Version: dep.Version,
		PURL:    dep.PackageURL,
	}

	if len(dep.Evidence) > 0 {
		occ := make([]Occurrence, len(dep.Evidence))
		for i, path := range dep.Evidence {
			occ[i] = Occurrence{Location: path}
		}
		c.Evidence = &ComponentEvidence{Occurrences: occ}
	}

	return c
}