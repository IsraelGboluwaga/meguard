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
//
// NETWORK, the ONE conditional flag: by default the sandbox gets --network none
// (no stack at all). When Execute has started an egress monitor for an
// InspectEgress run it sets p.NetworkContainer, and the sandbox instead joins
// that monitor's network namespace via --network container:<name>. That is
// still a no-egress configuration: the monitor's netns has no route out, only a
// sinkhole that logs and drops. The sandbox gains NO capability from joining;
// the netns rules are enforced by the kernel and the sandbox stays --cap-drop
// ALL, so it cannot alter them. Every other flag above is unconditional.
func createArgs(name string, p Profile) []string {
	p = p.Normalize()
	netMode := networkArgs(p)
	args := []string{
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
	}
	args = append(args, netMode...)
	args = append(args,
		"-w", "/repo",
		"-e", "HOME=/home/sandbox",
		// The image and the keep-alive command are the tail of the argv.
		p.Image,
		"sleep", "infinity",
	)
	return args
}

// networkArgs returns the network flag for the sandbox. It is the only part of
// createArgs that is not a fixed literal, and it is still no-egress in both
// branches: --network none (default) or joining the monitor's netns, whose only
// route is a logging sinkhole.
func networkArgs(p Profile) []string {
	if p.NetworkContainer != "" {
		return []string{"--network", "container:" + p.NetworkContainer}
	}
	return []string{"--network", "none"}
}
