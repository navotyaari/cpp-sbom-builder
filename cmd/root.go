package cmd

import (
	"flag"
	"fmt"
	"os"
)

// Execute parses CLI flags and runs the tool.
func Execute() {
	fs := flag.NewFlagSet("cpp-sbom-builder", flag.ContinueOnError)

	dir := fs.String("dir", "", "Path to the C++ project root to scan (required)")
	output := fs.String("output", "sbom.json", "Path for the output JSON file (default: sbom.json)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Suppress "output declared but not used" until later tasks wire it up.
	_ = output

	if *dir == "" {
		fmt.Fprintf(os.Stderr, "error: --dir is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	info, err := os.Stat(*dir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: --dir path does not exist or is not a directory: %q\n", *dir)
		os.Exit(1)
	}

	fmt.Println("Scan starting...")
}
