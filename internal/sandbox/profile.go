package sandbox

// Profile describes a sandbox configuration.
//
// SAFETY INVARIANT: the zero value is the safest possible Profile. Every
// security-relevant control (dropped capabilities, no-new-privileges, read-only
// root, tmpfs mounts, no network, non-root user) is hardcoded in the Docker
// argv (see createArgs) and is deliberately NOT represented as a field here, so
// a forgotten or zero-valued field can never open a hole. The fields below only
// ever RELAX conservative defaults: they choose an ecosystem image, an install
// command, and resource ceilings. When left empty they fall back to locked-down
// defaults via Normalize.
type Profile struct {
	// Image is the container image used for the sandbox. Empty means
	// DefaultImage. This is one of only two ecosystem-specific values in this
	// slice.
	Image string

	// InstallCmd is the command executed inside the sandbox to install the
	// repo's dependencies. Empty means DefaultInstallCmd. This is the second
	// and last ecosystem-specific value.
	//
	// TODO(tier-2): auto-detect the ecosystem (npm, pip, and so on) from repo
	// manifests instead of requiring --image and --cmd. Auto-detection is out
	// of scope for this slice.
	InstallCmd []string

	// Memory is the container memory ceiling passed to --memory. Empty means
	// DefaultMemory. This is a conservative default that will become
	// user-configurable; a large install may need more than 2g.
	Memory string

	// CPUs is the container CPU ceiling passed to --cpus. Empty means
	// DefaultCPUs. This is a conservative default that will become
	// user-configurable.
	CPUs string

	// PidsLimit caps the number of processes via --pids-limit. Zero means
	// DefaultPidsLimit.
	PidsLimit int
}

// Conservative defaults. These are ceilings and ecosystem choices only; none of
// them relaxes an isolation boundary.
const (
	DefaultImage     = "node:20-slim"
	DefaultMemory    = "2g"
	DefaultCPUs      = "2"
	DefaultPidsLimit = 512
)

// DefaultInstallCmd returns the default install command. It is a function so
// callers cannot mutate a shared slice.
func DefaultInstallCmd() []string { return []string{"npm", "install"} }

// Normalize returns a copy of p with empty fields replaced by their locked-down
// defaults. Normalize never removes or weakens a security control; it only
// fills in ecosystem and resource defaults.
func (p Profile) Normalize() Profile {
	out := p
	if out.Image == "" {
		out.Image = DefaultImage
	}
	if len(out.InstallCmd) == 0 {
		out.InstallCmd = DefaultInstallCmd()
	}
	if out.Memory == "" {
		out.Memory = DefaultMemory
	}
	if out.CPUs == "" {
		out.CPUs = DefaultCPUs
	}
	if out.PidsLimit == 0 {
		out.PidsLimit = DefaultPidsLimit
	}
	return out
}
