// Package cmd wires the meguard command-line interface using cobra.
//
// This package NEVER imports internal/analyze or any analyzer package. The run
// path's safety guarantee is independent of scan; keeping the dependency graph
// clean is a structural invariant enforced by a guard test in
// internal/sandbox.
package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "meguard",
		Short: "Safely execute untrusted repos inside a locked-down container sandbox",
		Long: `meguard runs untrusted repositories (for example fake-interview repos that
hide infostealer or RAT payloads) inside a locked-down container sandbox.

The repo is cloned or copied, then executed only inside a container that has no
network, no host bind mounts, dropped capabilities, and a read-only root. Repo
code never runs on the host.`,
		// Errors are reported once by main; do not also print usage on error.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd())
	return root
}

// Execute runs the meguard root command with the given context.
func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}
