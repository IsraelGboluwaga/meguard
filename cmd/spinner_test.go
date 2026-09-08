package cmd

import (
	"bytes"
	"testing"
)

// A non-terminal writer must stay pristine: the spinner is a convenience for
// interactive terminals and must never leak carriage returns or frames into
// piped or redirected output (that is what keeps `meguard scan | ...` clean).
func TestSpinnerNoOpOnNonTerminal(t *testing.T) {
	var buf bytes.Buffer
	sp := newSpinner(&buf)
	if sp.tty {
		t.Fatal("bytes.Buffer must not be detected as a terminal")
	}
	sp.start("working")
	sp.setLabel("still working")
	sp.stop()
	if buf.Len() != 0 {
		t.Fatalf("expected no output on non-terminal writer, got %q", buf.String())
	}
}

// The nil spinner is the "verbose mode" case (no spinner allocated). Every
// method must be safe on it so callers need no nil checks of their own.
func TestNilSpinnerIsSafe(t *testing.T) {
	var sp *spinner
	sp.start("working")
	sp.setLabel("still working")
	sp.stop()
}

// start/stop must be idempotent-safe: a second stop with no active animation,
// and a double start, must neither panic nor hang.
func TestSpinnerLifecycleIsSafe(t *testing.T) {
	var buf bytes.Buffer
	sp := newSpinner(&buf)
	sp.stop()          // stop before any start
	sp.start("a")      // start
	sp.start("b")      // redundant start is ignored
	sp.stop()          // stop
	sp.stop()          // redundant stop is ignored
}
