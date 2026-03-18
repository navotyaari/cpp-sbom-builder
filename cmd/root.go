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
	fileCh, err := walker.Walk(ctx, dir)
	if err != nil {
		return fmt.Errorf("walking %q: %w", dir, err)
	}

	cmake := detector.CMakeDetector{}
	cmake.W = w
	vcpkg := detector.VcpkgDetector{}
	vcpkg.W = w
	conan := detector.ConanDetector{}
	conan.W = w
	includes := detector.IncludeScanner{}
	includes.W = w
	detectors := []detector.Detector{cmake, vcpkg, conan, includes}

	detChans := fanOut(fileCh, detectors)

	allResults, err := runDetectors(ctx, w, detectors, detChans)
	if err != nil {
		return err
	}

	merged := merger.Merge(allResults)

	report, err := formatter.Format(merged, filepath.Base(dir))
	if err != nil {
		return fmt.Errorf("formatting SBOM: %w", err)
	}

	return writeOutput(outputPath, report, w)
}

// fanOut creates one buffered channel per detector, launches a goroutine that
// routes each path received from fileCh only to detectors whose Match returns
// true, and returns the channel slice. The fan-out goroutine closes all
// per-detector channels once fileCh is drained.
//
// Match is called here rather than inside each Detect implementation: it is
// intentionally cheap (a string comparison) so it does not become a bottleneck
// on the fan-out critical path, and calling it here reduces channel traffic so
// each file reaches only the detectors that care about it.
//
// detectorChBuf is sized to match the walker's own buffer so the fan-out
// goroutine can keep pace with the walker without blocking even if one detector
// is momentarily slow.
func fanOut(fileCh chan string, detectors []detector.Detector) []chan string {
	const detectorChBuf = 64
	detChans := make([]chan string, len(detectors))
	for i := range detChans {
		detChans[i] = make(chan string, detectorChBuf)
	}

	go func() {
		for path := range fileCh {
			// Send each path only to detectors that match it. Match is a fast
			// string comparison (nanoseconds) so the fan-out goroutine is never
			// the bottleneck. The blocking send below is safe because all
			// detector goroutines (launched in runDetectors) continuously drain
			// their channels; a detector goroutine stalling would block the
			// fan-out, which is a known limitation of the design.
			for i, d := range detectors {
				if d.Match(path) {
					detChans[i] <- path
				}
			}
		}
		for _, dc := range detChans {
			close(dc)
		}
	}()

	return detChans
}

// runDetectors launches one goroutine per detector. Each goroutine drains its
// per-detector channel into a []string, calls Detect, and sends the result to
// a shared results channel. runDetectors blocks until all detectors finish,
// then returns the collected dependency slices.
//
// Context cancellation is propagated: if ctx is cancelled while results are
// being collected, runDetectors returns ctx.Err() immediately.
func runDetectors(ctx context.Context, w io.Writer, detectors []detector.Detector, detChans []chan string) ([][]detector.Dependency, error) {
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
				return nil, ctx.Err()
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
		return nil, ctx.Err()
	}

	return allResults, nil
}

// writeOutput marshals report to indented JSON, writes it to outputPath, and
// prints a confirmation message to w.
func writeOutput(outputPath string, report formatter.SBOMReport, w io.Writer) error {
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