package detector

import (
	"io"
	"os"
)

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