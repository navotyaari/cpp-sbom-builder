// Package formatter serializes a merged dependency list to a CycloneDX 1.4
// JSON SBOM document.
package formatter

import (
	"time"

	"cpp-sbom-builder/internal/detector"
)

// ── CycloneDX 1.4 output structs ─────────────────────────────────────────────

// SBOMReport is the top-level CycloneDX 1.4 document.
type SBOMReport struct {
	BOMFormat   string     `json:"bomFormat"`
	SpecVersion string     `json:"specVersion"`
	Version     int        `json:"version"`
	Metadata    Metadata   `json:"metadata"`
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
	Type     string            `json:"type"`
	BOMRef   string            `json:"bom-ref"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	PURL     string            `json:"purl"`
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
	toolVendor  = "cpp-sbom-builder"
	toolName    = "cpp-sbom-builder"
	toolVersion = "1.0.0"
)

// Format converts a merged dependency slice into a CycloneDX 1.4 SBOMReport.
// projectName is used as the metadata.component name.
// If deps is nil or empty, Components is an empty (non-null) JSON array.
func Format(deps []detector.Dependency, projectName string) (SBOMReport, error) {
	components := make([]Component, 0, len(deps)) // never nil → serialises as []
	for _, dep := range deps {
		components = append(components, dependencyToComponent(dep))
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
				BOMRef:  projectName + "-unknown",
				Name:    projectName,
				Version: "unknown",
				PURL:    "",
			},
		},
		Components: components,
	}

	return report, nil
}

// dependencyToComponent maps a single Dependency to its Component representation.
func dependencyToComponent(dep detector.Dependency) Component {
	c := Component{
		Type:    "library",
		BOMRef:  dep.Name + "-" + dep.Version,
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
