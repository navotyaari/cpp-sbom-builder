// Package merger deduplicates and merges dependency slices from multiple
// detectors into a single canonical []Dependency sorted by name.
package merger

import (
	"slices"
	"sort"
	"strings"

	"cpp-sbom-builder/internal/detector"
)

// sourcePriority maps detector names to their confidence rank.
// Lower number = higher confidence.
var sourcepriority = map[string]int{
	"vcpkg":   1,
	"conan":   2,
	"cmake":   3,
	"include": 4,
}

// priorityOf returns the priority for a source name; unknown sources get a
// low-priority fallback so they are never preferred over known detectors.
func priorityOf(source string) int {
	if p, ok := sourcepriority[source]; ok {
		return p
	}
	return 99
}

// bestSource returns the highest-confidence source name from a slice.
func bestSource(sources []string) string {
	best := ""
	bestP := 100
	for _, s := range sources {
		if p := priorityOf(s); p < bestP {
			bestP = p
			best = s
		}
	}
	return best
}

// mergeEntry holds the working state while accumulating a single dependency.
type mergeEntry struct {
	dep detector.Dependency
	// versionBySource tracks the version each source reported so we can fall
	// back to a real version from a lower-priority source if the winner is
	// "unknown".
	versionBySource map[string]string
}

// Merge combines multiple []Dependency slices (one per detector) into a single
// deduplicated, sorted slice.
func Merge(results [][]detector.Dependency) []detector.Dependency {
	entries := map[string]*mergeEntry{}

	for _, slice := range results {
		for _, dep := range slice {
			key := strings.ToLower(dep.Name)
			if key == "" {
				continue
			}

			e, exists := entries[key]
			if !exists {
				e = &mergeEntry{
					dep: detector.Dependency{
						Name: key,
					},
					versionBySource: map[string]string{},
				}
				entries[key] = e
			}

			// Merge Sources (deduplicated).
			for _, src := range dep.Sources {
				if !slices.Contains(e.dep.Sources, src) {
					e.dep.Sources = append(e.dep.Sources, src)
				}
				// Record the version this source reported.
				if dep.Version != "" {
					e.versionBySource[src] = dep.Version
				}
			}

			// Merge Evidence (deduplicated).
			for _, ev := range dep.Evidence {
				if !slices.Contains(e.dep.Evidence, ev) {
					e.dep.Evidence = append(e.dep.Evidence, ev)
				}
			}
		}
	}

	// Resolve version for each merged entry.
	for _, e := range entries {
		e.dep.Version = resolveVersion(e.dep.Sources, e.versionBySource)
		e.dep.PackageURL = detector.BuildPURL(e.dep.Name, e.dep.Version)
	}

	// Collect and sort alphabetically by name.
	out := make([]detector.Dependency, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.dep)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})

	return out
}

// resolveVersion picks the best version from the versions reported by each
// source, respecting the confidence hierarchy.
//
// Algorithm:
//  1. Find the highest-priority source that reported a version.
//  2. If that version is "unknown", scan remaining sources (in priority order)
//     for the first real (non-"unknown") version and use it instead.
func resolveVersion(sources []string, versionBySource map[string]string) string {
	if len(versionBySource) == 0 {
		return "unknown"
	}

	// Sort sources by priority so we evaluate them highest-confidence first.
	sorted := make([]string, len(sources))
	copy(sorted, sources)
	sort.Slice(sorted, func(i, j int) bool {
		return priorityOf(sorted[i]) < priorityOf(sorted[j])
	})

	// First pass: find the version from the highest-priority source.
	winner := "unknown"
	for _, src := range sorted {
		if v, ok := versionBySource[src]; ok {
			winner = v
			break
		}
	}

	// Second pass: if winner is "unknown", use the first real version from any
	// lower-priority source.
	if winner == "unknown" {
		for _, src := range sorted {
			if v, ok := versionBySource[src]; ok && v != "unknown" {
				return v
			}
		}
	}

	return winner
}