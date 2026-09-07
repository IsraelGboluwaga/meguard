package sandbox

import "strconv"

// createArgs builds the full argument vector for `docker create`, everything
// after the `docker` binary itself. It is a pure function so the argv contract
// can be asserted by a test (see TestCreateArgsHardening).
//
// SAFETY INVARIANT: every hardening flag below is unconditional. None is derived
// from a Profile field, so no configuration and no forgotten field can remove
// one. Profile only supplies the image, the resource ceilings, and the install
// command (the last runs later via `docker exec`, not here). If a hardening flag
// is ever removed from this slice, the argv contract test fails.
//
// Each flag and the door it closes:
//
//	--user 1000:1000              never run as root inside the container
//	--cap-drop ALL                drop every Linux capability
//	--security-opt no-new-privileges  block setuid/privilege escalation
//	--read-only                   root filesystem is immutable
//	--tmpfs /repo:exec,mode=1777  repo lives in ephemeral RAM, execution allowed,
//	                              writable by the non-root sandbox user
//	--tmpfs /home/sandbox         scratch HOME in RAM, holds no host secrets
//	--tmpfs /tmp                  writable scratch in RAM only
//	--pids-limit 512              cap fork bombs
//	--memory 2g                   cap memory (conservative; will be configurable)
//	--cpus 2                      cap CPU (conservative; will be configurable)
//	--network none                no egress at all; kills stage-2 payload fetches
//	-w /repo                      work in the copied repo
//	-e HOME=/home/sandbox         HOME points at the scratch tmpfs, not host home
func createArgs(name string, p Profile) []string {
	p = p.Normalize()
	return []string{
		"create",
		"--name", name,
		"--user", "1000:1000",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		// mode=1777 lets the non-root sandbox user (uid 1000) write into the
		// tmpfs; the repo is streamed in and node_modules etc. are written here.
		"--tmpfs", "/repo:exec,mode=1777",
		"--tmpfs", "/home/sandbox",
		"--tmpfs", "/tmp",
		"--pids-limit", strconv.Itoa(p.PidsLimit),
		"--memory", p.Memory,
		"--cpus", p.CPUs,
		"--network", "none",
		"-w", "/repo",
		"-e", "HOME=/home/sandbox",
		// The image and the keep-alive command are the tail of the argv.
		p.Image,
		"sleep", "infinity",
	}
}
