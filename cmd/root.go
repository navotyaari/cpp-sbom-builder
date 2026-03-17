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
	"cpp-sbom-builder/internal/walker"
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

	if err := validateDir(*dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, os.Stderr, *dir, *output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// validateDir checks that dir is a non-empty path that exists and is a
// directory. It returns a descriptive error suitable for display to the user.
// The empty-string case is intentionally not handled here; Execute() catches
// that before calling validateDir so it can also print fs.Usage().
func validateDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("--dir path does not exist or is not a directory: %q", dir)
	}
	return nil
}

// Run executes the full SBOM pipeline. It is exported so that integration
// tests can call it directly without going through Execute or touching os.Exit.
// Diagnostic warnings are written to w. The pipeline respects ctx cancellation:
// if ctx is cancelled before all detectors complete, Run returns ctx.Err().
func Run(ctx context.Context, w io.Writer, dir, outputPath string) error {
	// ── Step 1: Start streaming filesystem walk ──────────────────────────────
	// Walk returns a channel immediately. File paths are sent into it as they
	// are discovered, so detectors begin receiving paths before the traversal
	// is complete. The channel is closed by the walker goroutine when done.
	fileCh, err := walker.Walk(ctx, dir)
	if err != nil {
		return fmt.Errorf("walking %q: %w", dir, err)
	}

	// ── Step 2: Fan the walker channel out to per-detector channels ──────────
	// Each detector receives its own buffered channel so that a slow detector
	// does not stall the fan-out goroutine and block the walker.
	detectors := []detector.Detector{
		detector.CMakeDetector{W: w},
		detector.VcpkgDetector{W: w},
		detector.ConanDetector{W: w},
		detector.IncludeScanner{W: w},
	}

	// detectorChBuf is sized to match walkBufSize so the fan-out goroutine can
	// keep pace with the walker without blocking even if one detector is slow.
	const detectorChBuf = 64
	detChans := make([]chan string, len(detectors))
	for i := range detChans {
		detChans[i] = make(chan string, detectorChBuf)
	}

	// Fan-out: read every path from the walker and broadcast it to all
	// per-detector channels, then close them when the walker channel closes.
	go func() {
		for path := range fileCh {
			// Blocking send — no select or cancellation check needed here.
			// All detector goroutines are already running (launched below) and
			// continuously draining their channels, so each send completes as
			// soon as the receiving goroutine's next loop iteration fires or the
			// per-detector buffer has room. If a detector goroutine were to stop
			// draining (e.g. due to a panic), this send would block indefinitely,
			// stalling the fan-out and walker goroutines. That is a known
			// limitation: the design assumes all detector goroutines run to
			// completion, which is enforced by the WaitGroup below.
			for _, dc := range detChans {
				dc <- path
			}
		}
		for _, dc := range detChans {
			close(dc)
		}
	}()

	// ── Step 3: Run all detectors concurrently ───────────────────────────────
	// Each detector goroutine drains its channel into a local []string then
	// calls Detect, keeping the Detector interface unchanged.
	type detResult struct {
		deps []detector.Dependency
		err  error
	}

	resultsCh := make(chan detResult, len(detectors))
	var wg sync.WaitGroup

	for i, d := range detectors {
		i, d := i, d
		wg.Add(1)
		go func() {
			defer wg.Done()
			var files []string
			for path := range detChans[i] {
				files = append(files, path)
			}
			deps, err := d.Detect(ctx, files)
			resultsCh <- detResult{deps: deps, err: err}
		}()
	}

	// Close results channel once all detectors finish.
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

	// Final cancellation check: covers both walker cancellation and any
	// cancellation that occurred after the results channel was drained.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// ── Step 4: Merge ─────────────────────────────────────────────────────────
	merged := merger.Merge(allResults)

	// ── Step 5: Format ────────────────────────────────────────────────────────
	projectName := filepath.Base(dir)
	report, err := formatter.Format(merged, projectName)
	if err != nil {
		return fmt.Errorf("formatting SBOM: %w", err)
	}

	// ── Step 6: Write output ─────────────────────────────────────────────────
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("serialising SBOM: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("writing %q: %w", outputPath, err)
	}

	fmt.Fprintf(w, "SBOM written to %s\n", outputPath)
	return nil
}