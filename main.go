// Command meguard safely executes untrusted repositories inside a locked-down
// container sandbox. This binary is pure Go (no cgo) so it ships as a single
// static file with fast startup and a small footprint.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/IsraelGboluwaga/meguard/cmd"
)

func main() {
	// A single signal-aware context is threaded through the whole run so that
	// Ctrl-C cancels in-flight work; sandbox cleanup then runs on a detached
	// context (see internal/sandbox.Execute).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cmd.Execute(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "meguard:", err)
		os.Exit(1)
	}
}
