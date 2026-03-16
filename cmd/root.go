package cmd

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"cpp-sbom-builder/internal/detector"
	"cpp-sbom-builder/internal/formatter"
	"cpp-sbom-builder/internal/merger"
)

// Execute parses CLI flags and runs the full SBOM pipeline.
func Execute() {
	fs := flag.NewFlagSet("cpp-sbom-builder", flag.ContinueOnError)

	dir := fs.String("dir", "", "Path to the C++ project root to scan (required)")
	output := fs.String("output", "sbom.json", "Path for the output JSON file (default: sbom.json)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, os.Stderr, *dir, *output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// Run executes the full SBOM pipeline. It is exported so that integration
// tests can call it directly without going through Execute or touching os.Exit.
// Diagnostic warnings are written to w. The pipeline respects ctx cancellation:
// if ctx is cancelled before all detectors complete, Run returns ctx.Err().
func Run(ctx context.Context, w io.Writer, dir, outputPath string) error {
	// ── Step 1: Run all detectors concurrently ───────────────────────────────
	detectors := []detector.Detector{
		detector.CMakeDetector{},
		detector.VcpkgDetector{},
		detector.ConanDetector{},
		detector.IncludeScanner{},
	}

	type detResult struct {
		deps []detector.Dependency
		err  error
	}

	resultsCh := make(chan detResult, len(detectors))
	var wg sync.WaitGroup

	for _, d := range detectors {
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			deps, err := d.Detect(ctx, dir)
			resultsCh <- detResult{deps: deps, err: err}
		}()
	}

	// Close channel once all detectors finish.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var allResults [][]detector.Dependency
	for r := range resultsCh {
		if r.err != nil {
			// Propagate context cancellation immediately.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Log detector errors but continue — one failing detector should
			// not abort the whole scan.
			fmt.Fprintf(w, "warning: detector error: %v\n", r.err)
			continue
		}
		allResults = append(allResults, r.deps)
	}

	// Final cancellation check after draining the results channel.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// ── Step 2: Merge ─────────────────────────────────────────────────────────
	merged := merger.Merge(allResults)

	// ── Step 3: Format ────────────────────────────────────────────────────────
	projectName := filepath.Base(dir)
	report, err := formatter.Format(merged, projectName)
	if err != nil {
		return fmt.Errorf("formatting SBOM: %w", err)
	}

	// ── Step 4: Write output ─────────────────────────────────────────────────
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("serialising SBOM: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing %q: %w", outputPath, err)
	}

	fmt.Printf("SBOM written to %s\n", outputPath)
	return nil
}