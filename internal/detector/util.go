package detector

import (
	"fmt"
	"io"
	"os"
)

// baseDetector holds the shared warning writer used by all detector
// implementations. If W is nil, warnings are written to os.Stderr.
// Embed this struct in a detector to get the warn helper for free.
type baseDetector struct {
	// W is the writer used for per-file warning messages. If nil, warnings
	// are written to os.Stderr.
	W io.Writer
}

// warn formats and writes a warning message to the configured writer,
// falling back to os.Stderr when W is nil.
func (b baseDetector) warn(format string, args ...any) {
	fmt.Fprintf(warnWriter(b.W), format, args...)
}

// warnWriter returns w if non-nil, otherwise os.Stderr.
// This preserves the zero-value behaviour of each detector struct: a detector
// constructed without an explicit W still writes warnings to os.Stderr, exactly
// as it did before this change.
func warnWriter(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stderr
}