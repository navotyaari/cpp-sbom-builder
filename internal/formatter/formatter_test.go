package formatter_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"cpp-sbom-builder/internal/detector"
	"cpp-sbom-builder/internal/formatter"
)

// sampleDep builds a minimal Dependency for use in tests.
func sampleDep(name, version, purl string, evidence ...string) detector.Dependency {
	return detector.Dependency{
		Name:       name,
		Version:    version,
		Sources:    []string{"vcpkg"},
		Evidence:   evidence,
		PackageURL: purl,
	}
}

func TestFormat_TopLevelFields(t *testing.T) {
	report, err := formatter.Format(nil, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if report.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", report.BOMFormat, "CycloneDX")
	}
	if report.SpecVersion != "1.4" {
		t.Errorf("SpecVersion = %q, want %q", report.SpecVersion, "1.4")
	}
	if report.Version != 1 {
		t.Errorf("Version = %d, want 1", report.Version)
	}
}

func TestFormat_MetadataTools(t *testing.T) {
	report, err := formatter.Format(nil, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if len(report.Metadata.Tools) != 1 {
		t.Fatalf("Tools len = %d, want 1", len(report.Metadata.Tools))
	}
	tool := report.Metadata.Tools[0]
	if tool.Name != "cpp-sbom-builder" {
		t.Errorf("Tool.Name = %q, want %q", tool.Name, "cpp-sbom-builder")
	}
	if tool.Vendor != "cpp-sbom-builder" {
		t.Errorf("Tool.Vendor = %q, want %q", tool.Vendor, "cpp-sbom-builder")
	}
	if tool.Version != "1.0.0" {
		t.Errorf("Tool.Version = %q, want %q", tool.Version, "1.0.0")
	}
}

func TestFormat_MetadataComponent(t *testing.T) {
	report, err := formatter.Format(nil, "my-app")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	mc := report.Metadata.Component
	if mc.Type != "application" {
		t.Errorf("metadata.component.type = %q, want %q", mc.Type, "application")
	}
	if mc.Name != "my-app" {
		t.Errorf("metadata.component.name = %q, want %q", mc.Name, "my-app")
	}
	if mc.Version != "unknown" {
		t.Errorf("metadata.component.version = %q, want %q", mc.Version, "unknown")
	}
}

func TestFormat_MetadataTimestamp(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)

	report, err := formatter.Format(nil, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	after := time.Now().UTC().Add(time.Second)

	ts, parseErr := time.Parse(time.RFC3339, report.Metadata.Timestamp)
	if parseErr != nil {
		t.Fatalf("Timestamp %q is not RFC3339: %v", report.Metadata.Timestamp, parseErr)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("Timestamp %q is outside expected range [%v, %v]", report.Metadata.Timestamp, before, after)
	}
}

func TestFormat_DependencyMapsToComponent(t *testing.T) {
	dep := sampleDep("openssl", "1.1.1", "pkg:generic/openssl@1.1.1", "/vcpkg.json")

	report, err := formatter.Format([]detector.Dependency{dep}, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if len(report.Components) != 1 {
		t.Fatalf("Components len = %d, want 1", len(report.Components))
	}

	c := report.Components[0]

	if c.Type != "library" {
		t.Errorf("Component.Type = %q, want %q", c.Type, "library")
	}
	if c.BOMRef != "openssl-1.1.1" {
		t.Errorf("Component.BOMRef = %q, want %q", c.BOMRef, "openssl-1.1.1")
	}
	if c.Name != "openssl" {
		t.Errorf("Component.Name = %q, want %q", c.Name, "openssl")
	}
	if c.Version != "1.1.1" {
		t.Errorf("Component.Version = %q, want %q", c.Version, "1.1.1")
	}
	if c.PURL != "pkg:generic/openssl@1.1.1" {
		t.Errorf("Component.PURL = %q, want %q", c.PURL, "pkg:generic/openssl@1.1.1")
	}
}

func TestFormat_EvidenceMapsToOccurrences(t *testing.T) {
	dep := sampleDep("zlib", "1.2.11", "pkg:generic/zlib@1.2.11",
		"/project/CMakeLists.txt", "/project/vcpkg.json")

	report, err := formatter.Format([]detector.Dependency{dep}, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	c := report.Components[0]
	if c.Evidence == nil {
		t.Fatal("Component.Evidence is nil, want non-nil")
	}
	if len(c.Evidence.Occurrences) != 2 {
		t.Fatalf("Occurrences len = %d, want 2", len(c.Evidence.Occurrences))
	}

	locs := map[string]bool{}
	for _, o := range c.Evidence.Occurrences {
		locs[o.Location] = true
	}
	for _, path := range []string{"/project/CMakeLists.txt", "/project/vcpkg.json"} {
		if !locs[path] {
			t.Errorf("Occurrence location %q missing", path)
		}
	}
}

// TestFormat_EmptyDepsProducesEmptyArray is the critical null-vs-empty check.
func TestFormat_EmptyDepsProducesEmptyArray(t *testing.T) {
	for _, label := range []string{"nil deps", "empty deps"} {
		var deps []detector.Dependency
		if label == "empty deps" {
			deps = []detector.Dependency{}
		}

		report, err := formatter.Format(deps, "myproject")
		if err != nil {
			t.Fatalf("[%s] Format() error: %v", label, err)
		}

		data, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			t.Fatalf("[%s] json.Marshal error: %v", label, marshalErr)
		}

		// The JSON must contain `"components":[]` not `"components":null`.
		if !strings.Contains(string(data), `"components":[]`) {
			t.Errorf("[%s] expected components:[] in JSON, got: %s", label, data)
		}
	}
}

// TestFormat_SerializesToValidJSON verifies the full document round-trips
// cleanly through encoding/json.
func TestFormat_SerializesToValidJSON(t *testing.T) {
	deps := []detector.Dependency{
		sampleDep("openssl", "1.1.1", "pkg:generic/openssl@1.1.1", "/vcpkg.json"),
		sampleDep("boost", "1.74.0", "pkg:generic/boost@1.74.0", "/CMakeLists.txt"),
	}

	report, err := formatter.Format(deps, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	data, marshalErr := json.MarshalIndent(report, "", "  ")
	if marshalErr != nil {
		t.Fatalf("json.MarshalIndent error: %v", marshalErr)
	}

	// Round-trip: unmarshal back into a generic map and spot-check.
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal round-trip error: %v", err)
	}

	if decoded["bomFormat"] != "CycloneDX" {
		t.Errorf("round-trip bomFormat = %v, want CycloneDX", decoded["bomFormat"])
	}
	if decoded["specVersion"] != "1.4" {
		t.Errorf("round-trip specVersion = %v, want 1.4", decoded["specVersion"])
	}
}

// TestFormat_NoEvidenceOmitsEvidenceField verifies that a dependency with no
// evidence paths produces a component without an "evidence" key in JSON.
func TestFormat_NoEvidenceOmitsEvidenceField(t *testing.T) {
	dep := detector.Dependency{
		Name:       "somelib",
		Version:    "1.0",
		PackageURL: "pkg:generic/somelib@1.0",
		Evidence:   nil,
	}

	report, err := formatter.Format([]detector.Dependency{dep}, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	data, _ := json.Marshal(report)
	if strings.Contains(string(data), `"evidence"`) {
		t.Errorf("expected no 'evidence' key for dep with no evidence paths, got: %s", data)
	}
}
