package main_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"cpp-sbom-builder/cmd"
	"cpp-sbom-builder/internal/formatter"
)

// sampleProjectDir returns the absolute path to testdata/sample_project.
func sampleProjectDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "sample_project")
}

// runPipeline executes the full pipeline against dir and returns the parsed
// SBOMReport written to a temp file.
func runPipeline(t *testing.T, dir string) formatter.SBOMReport {
	t.Helper()

	outFile := filepath.Join(t.TempDir(), "sbom.json")

	if err := cmd.Run(context.Background(), io.Discard, dir, outFile); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", outFile, err)
	}

	var report formatter.SBOMReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("json.Unmarshal: %v\nraw JSON:\n%s", err, data)
	}
	return report
}

// TestIntegration_TopLevelFields checks bomFormat and specVersion.
func TestIntegration_TopLevelFields(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	if report.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", report.BOMFormat, "CycloneDX")
	}
	if report.SpecVersion != "1.4" {
		t.Errorf("specVersion = %q, want %q", report.SpecVersion, "1.4")
	}
}

// TestIntegration_ComponentsNonEmpty asserts at least one component is detected.
func TestIntegration_ComponentsNonEmpty(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	if len(report.Components) == 0 {
		t.Fatal("components array is empty, expected at least one component")
	}
}

// TestIntegration_OpenSSLPresent asserts openssl appears in the component list.
func TestIntegration_OpenSSLPresent(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	for _, c := range report.Components {
		if c.Name == "openssl" {
			return // found
		}
	}
	t.Errorf("openssl not found in components; got: %v", componentNames(report.Components))
}

// TestIntegration_NoEmptyComponentName asserts no component has an empty name.
func TestIntegration_NoEmptyComponentName(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	for i, c := range report.Components {
		if c.Name == "" {
			t.Errorf("component[%d] has empty name field", i)
		}
	}
}

// TestIntegration_StdlibFiltered asserts "vector" and "string" are not
// present in the components (they are C++ stdlib headers).
func TestIntegration_StdlibFiltered(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	filtered := []string{"vector", "string", "iostream"}
	names := componentNames(report.Components)
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	for _, stdlib := range filtered {
		if nameSet[stdlib] {
			t.Errorf("stdlib header %q must not appear in components", stdlib)
		}
	}
}

// TestIntegration_JSONOutputIsValid unmarshals the raw output file into a
// generic map as a schema-agnostic validity check.
func TestIntegration_JSONOutputIsValid(t *testing.T) {
	dir := sampleProjectDir(t)
	outFile := filepath.Join(t.TempDir(), "sbom.json")

	if err := cmd.Run(context.Background(), io.Discard, dir, outFile); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}
}

// TestIntegration_MetadataToolPresent checks the generator tool entry.
func TestIntegration_MetadataToolPresent(t *testing.T) {
	report := runPipeline(t, sampleProjectDir(t))

	if len(report.Metadata.Tools) == 0 {
		t.Fatal("metadata.tools is empty")
	}
	if report.Metadata.Tools[0].Name != "cpp-sbom-builder" {
		t.Errorf("tool name = %q, want %q", report.Metadata.Tools[0].Name, "cpp-sbom-builder")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func componentNames(components []formatter.Component) []string {
	names := make([]string, len(components))
	for i, c := range components {
		names[i] = c.Name
	}
	return names
}