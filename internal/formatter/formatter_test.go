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
	if tool.Version == "" {
		t.Errorf("Tool.Version is empty; want a non-empty version string")
	}
}

// TestFormat_MetadataToolVersion_NonEmpty verifies that the tool version in
// the SBOM metadata is always non-empty.  The exact value depends on whether
// the binary was built with -ldflags version injection (release builds) or
// not (defaults to "dev"); either way it must not be blank.
func TestFormat_MetadataToolVersion_NonEmpty(t *testing.T) {
	report, err := formatter.Format(nil, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if len(report.Metadata.Tools) == 0 {
		t.Fatal("Metadata.Tools is empty")
	}
	if v := report.Metadata.Tools[0].Version; v == "" {
		t.Error("metadata.tools[0].version is empty; want a non-empty string (\"dev\" in local builds, a semver tag in release builds)")
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

// ── bom-ref uniqueness tests ──────────────────────────────────────────────────

// TestFormat_BOMRef_UniqueNameVersion verifies that two components sharing the
// same name but carrying distinct versions each get the plain name-version
// bom-ref with no suffix (the happy-path: no collision).
func TestFormat_BOMRef_UniqueNameVersion(t *testing.T) {
	deps := []detector.Dependency{
		sampleDep("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", "/vcpkg.json"),
		sampleDep("zlib", "1.3.0", "pkg:generic/zlib@1.3.0", "/other/vcpkg.json"),
	}

	report, err := formatter.Format(deps, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	wantRefs := []string{"zlib-1.2.11", "zlib-1.3.0"}
	for i, want := range wantRefs {
		got := report.Components[i].BOMRef
		if got != want {
			t.Errorf("Components[%d].BOMRef = %q, want %q", i, got, want)
		}
	}
}

// TestFormat_BOMRef_DuplicateNameVersionUnknown verifies that two components
// with the same name and version "unknown" receive distinct bom-refs.
// The first keeps the plain form; the second gets a "-2" suffix.
func TestFormat_BOMRef_DuplicateNameVersionUnknown(t *testing.T) {
	deps := []detector.Dependency{
		sampleDep("mylib", "unknown", "", "/include/mylib.h"),
		sampleDep("mylib", "unknown", "", "/src/mylib.h"),
	}

	report, err := formatter.Format(deps, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	if len(report.Components) != 2 {
		t.Fatalf("Components len = %d, want 2", len(report.Components))
	}

	ref0 := report.Components[0].BOMRef
	ref1 := report.Components[1].BOMRef

	if ref0 != "mylib-unknown" {
		t.Errorf("Components[0].BOMRef = %q, want %q", ref0, "mylib-unknown")
	}
	if ref1 != "mylib-unknown-2" {
		t.Errorf("Components[1].BOMRef = %q, want %q", ref1, "mylib-unknown-2")
	}

	// Uniqueness is the hard requirement.
	if ref0 == ref1 {
		t.Errorf("bom-ref values are not unique: both = %q", ref0)
	}
}

// TestFormat_BOMRef_MixedUniquenessAndDuplicates verifies correct behaviour
// when some name-version pairs are unique and others collide.
// Expected assignments (in input order):
//
//	openssl-1.1.1      → "openssl-1.1.1"      (unique, no suffix)
//	curl-unknown [1]   → "curl-unknown"        (first occurrence, no suffix)
//	curl-unknown [2]   → "curl-unknown-2"      (collision → suffix)
//	boost-1.74.0       → "boost-1.74.0"        (unique, no suffix)
//	curl-unknown [3]   → "curl-unknown-3"      (third occurrence → suffix)
func TestFormat_BOMRef_MixedUniquenessAndDuplicates(t *testing.T) {
	deps := []detector.Dependency{
		sampleDep("openssl", "1.1.1", "pkg:generic/openssl@1.1.1", "/vcpkg.json"),
		sampleDep("curl", "unknown", "", "/include/curl.h"),
		sampleDep("curl", "unknown", "", "/src/curl.h"),
		sampleDep("boost", "1.74.0", "pkg:generic/boost@1.74.0", "/CMakeLists.txt"),
		sampleDep("curl", "unknown", "", "/lib/curl.h"),
	}

	report, err := formatter.Format(deps, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	want := []string{
		"openssl-1.1.1",
		"curl-unknown",
		"curl-unknown-2",
		"boost-1.74.0",
		"curl-unknown-3",
	}

	if len(report.Components) != len(want) {
		t.Fatalf("Components len = %d, want %d", len(report.Components), len(want))
	}

	for i, w := range want {
		got := report.Components[i].BOMRef
		if got != w {
			t.Errorf("Components[%d].BOMRef = %q, want %q", i, got, w)
		}
	}

	// Global uniqueness check across all bom-refs including the root component.
	allRefs := make(map[string]int)
	allRefs[report.Metadata.Component.BOMRef]++
	for _, c := range report.Components {
		allRefs[c.BOMRef]++
	}
	for ref, count := range allRefs {
		if count > 1 {
			t.Errorf("bom-ref %q appears %d times; must be unique", ref, count)
		}
	}
}

// TestFormat_BOMRef_RootComponentIncludedInUniquenessCheck verifies that when
// a dependency would naturally produce the same bom-ref as the root metadata
// component, it receives a suffix instead.
func TestFormat_BOMRef_RootComponentIncludedInUniquenessCheck(t *testing.T) {
	// The root component gets bom-ref "myproject-unknown".
	// A dependency named "myproject" with version "unknown" would collide.
	dep := sampleDep("myproject", "unknown", "", "/include/myproject.h")

	report, err := formatter.Format([]detector.Dependency{dep}, "myproject")
	if err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	rootRef := report.Metadata.Component.BOMRef
	depRef := report.Components[0].BOMRef

	if rootRef == depRef {
		t.Errorf("root bom-ref %q collides with component bom-ref %q", rootRef, depRef)
	}
}