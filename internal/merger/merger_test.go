package merger_test

import (
	"testing"

	"cpp-sbom-builder/internal/detector"
	"cpp-sbom-builder/internal/merger"
)

// dep is a convenience constructor for test fixtures.
func dep(name, version, source, evidence string) detector.Dependency {
	return detector.Dependency{
		Name:       name,
		Version:    version,
		Sources:    []string{source},
		Evidence:   []string{evidence},
		PackageURL: detector.BuildPURL(name, version),
	}
}

// TestMerge_SameDepFromTwoDetectors verifies that two entries with the same
// name produce exactly one output entry with merged Sources and Evidence.
func TestMerge_SameDepFromTwoDetectors(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("openssl", "1.1.1", "vcpkg", "/vcpkg.json")},
		{dep("openssl", "1.1.1", "cmake", "/CMakeLists.txt")},
	}

	got := merger.Merge(input)

	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d: %v", len(got), got)
	}
	d := got[0]
	if d.Name != "openssl" {
		t.Errorf("Name = %q, want %q", d.Name, "openssl")
	}
	if !containsAll(d.Sources, "vcpkg", "cmake") {
		t.Errorf("Sources = %v, want both vcpkg and cmake", d.Sources)
	}
	if !containsAll(d.Evidence, "/vcpkg.json", "/CMakeLists.txt") {
		t.Errorf("Evidence = %v, want both paths", d.Evidence)
	}
}

// TestMerge_HigherPriorityVersionWins verifies that vcpkg beats cmake when
// both report different concrete versions.
func TestMerge_HigherPriorityVersionWins(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("openssl", "3.0.0", "cmake", "/CMakeLists.txt")},
		{dep("openssl", "1.1.1", "vcpkg", "/vcpkg.json")},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(got))
	}
	if got[0].Version != "1.1.1" {
		t.Errorf("Version = %q, want %q (vcpkg should win over cmake)", got[0].Version, "1.1.1")
	}
}

// TestMerge_UnknownVersionOverriddenByRealVersion verifies that "unknown" from
// a high-priority source is replaced by a real version from a lower-priority
// source.
func TestMerge_UnknownVersionOverriddenByRealVersion(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("zlib", "unknown", "vcpkg", "/vcpkg.json")},
		{dep("zlib", "1.2.11", "cmake", "/CMakeLists.txt")},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(got))
	}
	if got[0].Version != "1.2.11" {
		t.Errorf("Version = %q, want %q (real version should override unknown)", got[0].Version, "1.2.11")
	}
}

// TestMerge_SortedAlphabetically verifies the output slice is sorted by name.
func TestMerge_SortedAlphabetically(t *testing.T) {
	input := [][]detector.Dependency{
		{
			dep("zlib", "1.2.11", "cmake", "/CMakeLists.txt"),
			dep("openssl", "1.1.1", "vcpkg", "/vcpkg.json"),
			dep("boost", "1.74.0", "conan", "/conanfile.txt"),
		},
	}

	got := merger.Merge(input)
	want := []string{"boost", "openssl", "zlib"}

	if len(got) != len(want) {
		t.Fatalf("expected %d deps, got %d", len(want), len(got))
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("got[%d].Name = %q, want %q", i, got[i].Name, name)
		}
	}
}

// TestMerge_PackageURLRecalculated verifies that PackageURL reflects the final
// resolved name and version, not the one from an individual detector.
func TestMerge_PackageURLRecalculated(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("openssl", "unknown", "include", "/main.cpp")},
		{dep("openssl", "1.1.1", "conan", "/conanfile.txt")},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(got))
	}
	wantPURL := detector.BuildPURL("openssl", "1.1.1")
	if got[0].PackageURL != wantPURL {
		t.Errorf("PackageURL = %q, want %q", got[0].PackageURL, wantPURL)
	}
}

// TestMerge_EvidenceDeduplication verifies that the same file path appearing
// in multiple detector results is not duplicated in Evidence.
func TestMerge_EvidenceDeduplication(t *testing.T) {
	sharedPath := "/CMakeLists.txt"
	input := [][]detector.Dependency{
		{dep("boost", "1.74", "cmake", sharedPath)},
		{dep("boost", "1.74", "include", sharedPath)},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(got))
	}
	count := 0
	for _, ev := range got[0].Evidence {
		if ev == sharedPath {
			count++
		}
	}
	if count != 1 {
		t.Errorf("path %q appears %d times in Evidence, want exactly 1", sharedPath, count)
	}
}

// TestMerge_NilAndEmptyInputs verifies graceful handling of nil/empty slices.
func TestMerge_NilAndEmptyInputs(t *testing.T) {
	tests := []struct {
		name  string
		input [][]detector.Dependency
	}{
		{"nil input", nil},
		{"empty outer slice", [][]detector.Dependency{}},
		{"empty inner slices", [][]detector.Dependency{{}, {}, {}}},
		{"mixed nil and non-nil", [][]detector.Dependency{nil, {dep("zlib", "1.2.11", "cmake", "/f")}, nil}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := merger.Merge(tc.input)
			// Should not panic; result count depends on input.
			_ = got
		})
	}
}

// TestMerge_NameNormalisedToLowercase verifies that deps with different cases
// for the same name are merged into one entry.
func TestMerge_NameNormalisedToLowercase(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("OpenSSL", "1.1.1", "cmake", "/CMakeLists.txt")},
		{dep("openssl", "1.1.1", "vcpkg", "/vcpkg.json")},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep after case-normalisation, got %d: %v", len(got), got)
	}
	if got[0].Name != "openssl" {
		t.Errorf("Name = %q, want %q", got[0].Name, "openssl")
	}
}

// TestMerge_AllUnknownVersionsStayUnknown verifies that when every source
// reports "unknown" the output version is also "unknown".
func TestMerge_AllUnknownVersionsStayUnknown(t *testing.T) {
	input := [][]detector.Dependency{
		{dep("somelib", "unknown", "include", "/a.cpp")},
		{dep("somelib", "unknown", "cmake", "/CMakeLists.txt")},
	}

	got := merger.Merge(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(got))
	}
	if got[0].Version != "unknown" {
		t.Errorf("Version = %q, want %q", got[0].Version, "unknown")
	}
}

// TestMerge_PriorityHierarchyFull exercises all four priority levels in order.
func TestMerge_PriorityHierarchyFull(t *testing.T) {
	tests := []struct {
		name        string
		higher      string
		higherVer   string
		lower       string
		lowerVer    string
		wantVersion string
	}{
		{"vcpkg over conan", "vcpkg", "1.0", "conan", "2.0", "1.0"},
		{"conan over cmake", "conan", "1.0", "cmake", "2.0", "1.0"},
		{"cmake over include", "cmake", "1.0", "include", "2.0", "1.0"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			input := [][]detector.Dependency{
				{dep("lib", tc.lowerVer, tc.lower, "/f1")},
				{dep("lib", tc.higherVer, tc.higher, "/f2")},
			}
			got := merger.Merge(input)
			if len(got) != 1 {
				t.Fatalf("expected 1 dep, got %d", len(got))
			}
			if got[0].Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", got[0].Version, tc.wantVersion)
			}
		})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsAll(slice []string, vals ...string) bool {
	set := make(map[string]bool, len(slice))
	for _, s := range slice {
		set[s] = true
	}
	for _, v := range vals {
		if !set[v] {
			return false
		}
	}
	return true
}