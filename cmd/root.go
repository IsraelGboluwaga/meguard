// Package cmd wires the meguard command-line interface using cobra.
//
// This package DOES import internal/analyze: "run" combines the sandbox with
// a static scan, and "scan" runs the static scan alone. What must never
// import internal/analyze is internal/sandbox: the sandbox's containment
// guarantee is structurally independent of scan, so a bug in scan cannot
// weaken it (and a bug in the sandbox cannot silently disable scan). That
// separation is enforced by a guard test in internal/sandbox
// (TestSandboxDoesNotImportAnalyze), which checks internal/sandbox's
// dependency graph, not this package's.
package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// version is the release version, injected at build time by goreleaser via
// -ldflags "-X github.com/IsraelGboluwaga/meguard/cmd.version=...". It is "dev"
// for local and source builds.
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:     "meguard",
		Version: version,
		Short:   "Safely execute untrusted repos inside a locked-down container sandbox",
		Long: `meguard runs untrusted repositories (for example fake-interview repos that
hide infostealer or RAT payloads) inside a locked-down container sandbox.

The repo is cloned or copied, then executed only inside a container that has no
network, no host bind mounts, dropped capabilities, and a read-only root. Repo
code never runs on the host.

"run" also statically scans the repo before running it (container AND
detector, in one command); "scan" runs that same detection alone, without a
container.`,
		// Errors are reported once by main; do not also print usage on error.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd())
	root.AddCommand(newScanCmd())
	return root
}

// Execute runs the meguard root command with the given context.
func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}
