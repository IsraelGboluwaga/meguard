package sandbox

import (
	"context"
	"strconv"
	"strings"
)

// DefaultMonitorImage is the image used for the egress monitor sidecar. It must
// provide ip (iproute2), iptables, ip6tables, and a tcpdump built with NFLOG
// capture support (nicolaka/netshoot satisfies all of these). The monitor runs
// NO repo code; it only seals its netns and captures packets. It is configurable
// so an operator can pin a trusted, locally cached image (see --monitor-image).
const DefaultMonitorImage = "nicolaka/netshoot"

// The sinkhole next-hop and its static neighbour. A default route via this
// next-hop on a dummy interface exists ONLY so that a connect() to an external
// address produces a packet that reaches the OUTPUT chain (where it is logged
// and dropped) instead of failing early with ENETUNREACH and leaving nothing to
// log. The packet is never actually transmitted: the fail-closed OUTPUT DROP
// policy discards it in-chain, after NFLOG has copied it for capture.
const (
	sinkholeNextHop = "10.255.255.2"
	sinkholeLLAddr  = "02:00:00:00:00:01"
	// nflogGroup is the netlink group iptables copies packets to and tcpdump
	// reads from (tcpdump -i nflog:<group>). Capture happens IN the OUTPUT chain,
	// before the DROP policy, so it is independent of the egress interface name.
	nflogGroup = "30"
)

// EgressInspector is an OPTIONAL Runner capability. A Runner that also
// implements it can stand up a packet-level egress monitor sidecar whose
// network namespace the sandbox joins. Execute type-asserts for it only when
// Profile.InspectEgress is set, so a Runner that does not implement it is
// unaffected and the default (--network none) path never touches this code.
//
// TRUST NOTE: the monitor is a fixed helper that runs NO untrusted repo code. It
// is the one component granted NET_ADMIN/NET_RAW (to program the sinkhole and
// sniff), and only inside its own network namespace. The sandbox that joins it
// keeps --cap-drop ALL and gains nothing.
type EgressInspector interface {
	// StartMonitor creates and starts the egress monitor and returns its
	// container name. The caller passes that name to the sandbox via
	// Profile.NetworkContainer so the sandbox joins the monitor's netns, and is
	// responsible for removing the monitor via Runner.Remove.
	StartMonitor(ctx context.Context, p Profile) (monitorName string, err error)

	// CollectEgress fetches everything the monitor captured and returns the
	// deduplicated, ordered list of blocked outbound attempts. It is
	// best-effort: a monitor that captured nothing yields an empty slice.
	CollectEgress(ctx context.Context, monitorName string) ([]EgressEvent, error)
}

// EgressEvent is a single outbound connection attempt the monitor observed and
// dropped.
type EgressEvent struct {
	// Proto is "tcp" for a connection attempt (SYN) or "dns" for a name lookup.
	Proto string
	// Dest is the destination: "ip:port" for tcp, the queried name for dns.
	Dest string
}

// String renders an event as a single reporting line.
func (e EgressEvent) String() string {
	return "BLOCKED " + e.Proto + " " + e.Dest
}

// monitorImage returns the image to use for the monitor sidecar.
func monitorImage(p Profile) string {
	if p.MonitorImage != "" {
		return p.MonitorImage
	}
	return DefaultMonitorImage
}

// MonitorImageOrDefault reports the egress monitor image that would be used,
// resolving the empty default. It is exported for the CLI's pre-run notice.
func (p Profile) MonitorImageOrDefault() string { return monitorImage(p) }

// monitorCreateArgs builds the `docker create` argv for the egress monitor.
//
// The monitor is hardened like the sandbox (cap-drop ALL, no-new-privileges,
// read-only root, resource caps) but differs deliberately in two ways, because
// it runs fixed helper commands and NO repo code:
//   - it adds back ONLY NET_ADMIN (to program routes/iptables) and NET_RAW (for
//     tcpdump). Nothing else.
//   - it runs on a normal bridge so a real interface exists to neutralize; the
//     monitor command then tears down the real route and installs the sinkhole,
//     so the shared netns has no path out before the sandbox ever joins it.
func monitorCreateArgs(name string, p Profile) []string {
	p = p.Normalize()
	return []string{
		"create",
		"--name", name,
		// root inside the monitor: iptables/ip/tcpdump need the added caps to be
		// effective. no-new-privileges + cap-drop ALL keep it to exactly the two
		// added caps and nothing escalatable.
		"--user", "0:0",
		"--cap-drop", "ALL",
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_RAW",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp",
		"--pids-limit", "128",
		"--memory", "256m",
		"--cpus", "1",
		monitorImage(p),
		"sh", "-c", monitorScript(),
	}
}

// monitorScript is the shell run inside the monitor. It seals the network
// namespace FAIL-CLOSED and only then declares readiness:
//
//  1. It brings up a dummy sinkhole interface and points the default route at it,
//     purely so connect() to an external address produces a packet that reaches
//     the OUTPUT chain (rather than failing with ENETUNREACH and logging nothing).
//  2. It forces ALL DNS (including Docker's embedded 127.0.0.11 resolver) to the
//     sinkhole so a lookup is generated and logged but never forwarded upstream.
//  3. It logs every non-loopback packet via NFLOG (non-terminating) and then
//     sets the OUTPUT policy to DROP. The DROP policy, not an interface-specific
//     rule, is what enforces no-egress, so it does NOT depend on the uplink being
//     named eth0 and it cannot be bypassed by a route the script did not remove.
//  4. It seals IPv6 the same way when an IPv6 stack is present.
//  5. It VERIFIES the DROP policy and NFLOG rule actually applied, and only then
//     prints the readiness marker. Every setup command runs WITHOUT `|| true` (set
//     -e aborts on any failure), so a partial seal never prints the marker. The
//     caller waits for that marker before creating the sandbox, so the sandbox is
//     never created against an unsealed netns (fail closed).
//
// Capture (tcpdump on the nflog group) is best-effort and runs AFTER the seal is
// verified: losing capture loses logs, never containment, because the DROP policy
// already holds.
//
// LIVE-VERIFICATION NOTE: the Go orchestration, argv, and parser are unit tested,
// and this script is now fail-closed by construction, but the in-container
// netns/iptables/NFLOG behavior must still be verified once on a real Linux
// Docker host (NFLOG needs the nfnetlink_log module; tcpdump must support
// -i nflog:<group>).
func monitorScript() string {
	lines := []string{
		"set -e",
		// Sinkhole route so connect() generates a packet that traverses OUTPUT.
		"ip link add sink0 type dummy",
		"ip addr add 10.255.255.1/24 dev sink0",
		"ip link set sink0 up",
		"ip neigh replace " + sinkholeNextHop + " lladdr " + sinkholeLLAddr + " dev sink0 nud permanent",
		// Removing a possibly-absent default route is the one optional step.
		"ip route del default 2>/dev/null || true",
		"ip route add default via " + sinkholeNextHop + " dev sink0",
		"ip -6 route del default 2>/dev/null || true",
		// Force every DNS query (any destination, including 127.0.0.11) to the
		// sinkhole so it is generated and logged but never forwarded.
		"iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination " + sinkholeNextHop + ":53",
		"iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination " + sinkholeNextHop + ":53",
		// Fail-closed filter: accept loopback, log everything else, then DROP by
		// policy. Interface-independent; no `|| true`, so any failure aborts.
		"iptables -A OUTPUT -o lo -j ACCEPT",
		"iptables -A OUTPUT -j NFLOG --nflog-group " + nflogGroup,
		"iptables -P OUTPUT DROP",
		// Seal IPv6 identically when the stack exists; if it does not, there is
		// no v6 egress to seal.
		"if [ -d /proc/sys/net/ipv6 ]; then",
		"  ip6tables -A OUTPUT -o lo -j ACCEPT",
		"  ip6tables -A OUTPUT -j NFLOG --nflog-group " + nflogGroup,
		"  ip6tables -P OUTPUT DROP",
		"fi",
		// Verify the seal actually applied before declaring readiness. If either
		// check fails, set -e aborts and the marker is never printed.
		"iptables -S OUTPUT | grep -q '^-P OUTPUT DROP'",
		"iptables -C OUTPUT -j NFLOG --nflog-group " + nflogGroup,
		"echo " + monitorReadyMarker,
		// Capture in the OUTPUT chain via NFLOG (before the DROP), so every
		// non-loopback packet is seen regardless of egress interface. -n avoids
		// reverse lookups (which would themselves be egress); -l line-buffers.
		"exec tcpdump -i nflog:" + nflogGroup + " -n -l",
	}
	return strings.Join(lines, "\n")
}

// monitorReadyMarker is printed by the monitor once the sinkhole is in place.
const monitorReadyMarker = "meguard-egress-monitor-ready"

// monitorLogsArgs builds `docker logs <name>` to pull everything the monitor
// captured after the run.
func monitorLogsArgs(name string) []string {
	return []string{"logs", name}
}

// parseEgress turns raw tcpdump output into a deduplicated, ordered list of
// blocked attempts. It is a pure function so it can be unit tested without a
// container. Unrecognized lines (the ready marker, tcpdump banners, blank
// lines) are ignored.
func parseEgress(raw string) []EgressEvent {
	var out []EgressEvent
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		ev, ok := parseTcpdumpLine(line)
		if !ok {
			continue
		}
		key := ev.Proto + " " + ev.Dest
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ev)
	}
	return out
}

// parseTcpdumpLine parses a single tcpdump line into an EgressEvent.
//
// tcpdump `-n` output looks like:
//
//	IP 10.255.255.1.54321 > 185.220.101.5.443: Flags [S], seq ...
//	IP 10.255.255.1.51000 > 10.255.255.2.53: 1234+ A? api.evil-c2.net. (33)
//
// The token after ">" is "<ip>.<port>"; a trailing ":" is stripped. A DNS query
// is recognized by the "A?"/"AAAA?" marker, in which case the queried name is
// preferred over the sinkhole destination.
func parseTcpdumpLine(line string) (EgressEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, monitorReadyMarker) {
		return EgressEvent{}, false
	}
	fields := strings.Fields(line)
	gt := indexOf(fields, ">")
	if gt < 0 || gt+1 >= len(fields) {
		return EgressEvent{}, false
	}
	dest := strings.TrimSuffix(fields[gt+1], ":")

	// DNS: "A?"/"AAAA?" followed by the queried name (with a trailing dot).
	for i, f := range fields {
		if (f == "A?" || f == "AAAA?") && i+1 < len(fields) {
			name := strings.TrimSuffix(fields[i+1], ".")
			if name != "" {
				return EgressEvent{Proto: "dns", Dest: name}, true
			}
		}
	}

	ip, port, ok := splitHostPort(dest)
	if !ok {
		return EgressEvent{}, false
	}
	// A DNS destination we could not decode by name still reports as the lookup
	// attempt rather than a bare tcp line to the sinkhole resolver.
	if port == "53" {
		return EgressEvent{Proto: "dns", Dest: ip + ":53"}, true
	}
	return EgressEvent{Proto: "tcp", Dest: ip + ":" + port}, true
}

// splitHostPort splits tcpdump's "a.b.c.d.port" destination into host and port.
// tcpdump renders the port as the final dot-separated element, so the last dot
// separates host from port.
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ".")
	if i <= 0 || i+1 >= len(s) {
		return "", "", false
	}
	host, port = s[:i], s[i+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return "", "", false
	}
	return host, port, true
}

func indexOf(ss []string, target string) int {
	for i, s := range ss {
		if s == target {
			return i
		}
	}
	return -1
}
