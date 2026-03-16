package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDir(t *testing.T) {
	// Prepare a real temporary directory and a real file for path-based cases.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "notadir.txt")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}

	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string // substring that must appear in the error message
	}{
		{
			name:        "empty string",
			input:       "",
			wantErr:     true,
			errContains: "does not exist or is not a directory",
		},
		{
			name:        "path does not exist",
			input:       filepath.Join(tmpDir, "no-such-path"),
			wantErr:     true,
			errContains: "does not exist or is not a directory",
		},
		{
			name:        "path exists but is a file",
			input:       tmpFile,
			wantErr:     true,
			errContains: "does not exist or is not a directory",
		},
		{
			name:    "valid directory",
			input:   tmpDir,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDir(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateDir(%q) = nil, want error", tc.input)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("validateDir(%q) error = %q, want it to contain %q",
						tc.input, err.Error(), tc.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateDir(%q) = %v, want nil", tc.input, err)
				}
			}
		})
	}
}