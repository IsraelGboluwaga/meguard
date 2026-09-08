package cmd

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// spinner is a minimal, dependency-free progress indicator for the compact
// (non--verbose) run/scan path, where the slow stages (repo clone, static
// scan, and the in-container install) would otherwise print nothing and look
// frozen. It animates a single in-place line on stderr so it never
// contaminates the report on stdout, and it degrades to a no-op when stderr
// is not a terminal (piped or redirected), keeping non-interactive output
// clean. Frames are plain ASCII by house rule (no fancy Unicode glyphs).
type spinner struct {
	w     io.Writer
	tty   bool
	mu    sync.Mutex
	label string
	stopCh chan struct{}
	done   chan struct{}
}

var spinnerFrames = []rune{'|', '/', '-', '\\'}

// newSpinner returns a spinner writing to w. When w is not a terminal the
// spinner is inert: start/setLabel/stop all become no-ops, so callers need no
// TTY checks of their own.
func newSpinner(w io.Writer) *spinner {
	return &spinner{w: w, tty: isTerminal(w)}
}

// start begins animating with the given label. It is safe to call once; a
// second start without an intervening stop is ignored.
func (s *spinner) start(label string) {
	if s == nil || !s.tty {
		return
	}
	s.mu.Lock()
	if s.stopCh != nil {
		s.mu.Unlock()
		return
	}
	s.label = label
	stopCh := make(chan struct{})
	done := make(chan struct{})
	s.stopCh = stopCh
	s.done = done
	s.mu.Unlock()

	// stopCh and done are captured by value so the goroutine never races with
	// stop() clearing the struct fields.
	go s.run(stopCh, done)
}

func (s *spinner) run(stopCh, done chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-stopCh:
			close(done)
			return
		case <-ticker.C:
			s.mu.Lock()
			label := s.label
			s.mu.Unlock()
			fmt.Fprintf(s.w, "\r%c %s", spinnerFrames[frame%len(spinnerFrames)], label)
			frame++
		}
	}
}

// setLabel updates the text shown next to the animation.
func (s *spinner) setLabel(label string) {
	if s == nil || !s.tty {
		return
	}
	s.mu.Lock()
	s.label = label
	s.mu.Unlock()
}

// stop halts the animation and clears the line, leaving the cursor at column
// zero so the caller's next write starts on a clean line.
func (s *spinner) stop() {
	if s == nil || !s.tty {
		return
	}
	s.mu.Lock()
	if s.stopCh == nil {
		s.mu.Unlock()
		return
	}
	width := len(s.label) + 2
	close(s.stopCh)
	done := s.done
	s.stopCh = nil
	s.done = nil
	s.mu.Unlock()

	<-done
	// Overwrite the animated line with spaces, then return to column zero.
	fmt.Fprintf(s.w, "\r%*s\r", width, "")
}

// isTerminal reports whether w is a character device (an interactive
// terminal). It uses only os.File.Stat so the run binary stays cgo-free and
// needs no external terminal dependency.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
