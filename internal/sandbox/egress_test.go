package sandbox

import (
	"reflect"
	"testing"
)

// TestParseEgress covers the tcpdump line parser: SYNs to hardcoded IPs, DNS
// queries by name, dedup, and the noise lines that must be ignored.
func TestParseEgress(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []EgressEvent
	}{
		{
			name: "empty",
			raw:  "",
			want: nil,
		},
		{
			name: "only noise is ignored",
			raw: "meguard-egress-monitor-ready\n" +
				"tcpdump: listening on sink0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n",
			want: nil,
		},
		{
			name: "hardcoded IP SYN is captured",
			raw:  "IP 10.255.255.1.54321 > 185.220.101.5.443: Flags [S], seq 123, win 64240, length 0",
			want: []EgressEvent{{Proto: "tcp", Dest: "185.220.101.5:443"}},
		},
		{
			name: "DNS query captured by name",
			raw:  "IP 10.255.255.1.51000 > 10.255.255.2.53: 1234+ A? api.evil-c2.net. (33)",
			want: []EgressEvent{{Proto: "dns", Dest: "api.evil-c2.net"}},
		},
		{
			name: "AAAA query captured by name",
			raw:  "IP 10.255.255.1.51000 > 10.255.255.2.53: 5+ AAAA? pool.supportxmr.com. (37)",
			want: []EgressEvent{{Proto: "dns", Dest: "pool.supportxmr.com"}},
		},
		{
			name: "duplicates collapse, order preserved",
			raw: "IP 10.255.255.1.1 > 1.2.3.4.443: Flags [S], seq 1\n" +
				"IP 10.255.255.1.2 > 1.2.3.4.443: Flags [S], seq 2\n" +
				"IP 10.255.255.1.3 > 9.9.9.9.80: Flags [S], seq 3\n",
			want: []EgressEvent{
				{Proto: "tcp", Dest: "1.2.3.4:443"},
				{Proto: "tcp", Dest: "9.9.9.9:80"},
			},
		},
		{
			name: "mixed dns and tcp",
			raw: "IP 10.255.255.1.5 > 10.255.255.2.53: 1+ A? c2.example. (24)\n" +
				"IP 10.255.255.1.6 > 203.0.113.9.4444: Flags [S], seq 7\n",
			want: []EgressEvent{
				{Proto: "dns", Dest: "c2.example"},
				{Proto: "tcp", Dest: "203.0.113.9:4444"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEgress(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEgress(%q)\n = %#v\nwant %#v", tt.raw, got, tt.want)
			}
		})
	}
}

// TestMonitorCreateArgsHardening asserts the monitor sidecar is hardened and
// gets ONLY the two capabilities it needs, never more.
func TestMonitorCreateArgsHardening(t *testing.T) {
	got := monitorCreateArgs("meguard-egress-test", Profile{})

	requiredPairs := [][]string{
		{"--cap-drop", "ALL"},
		{"--cap-add", "NET_ADMIN"},
		{"--cap-add", "NET_RAW"},
		{"--security-opt", "no-new-privileges"},
		{"--read-only"},
		{"--tmpfs", "/tmp"},
		{"--pids-limit", "128"},
	}
	for _, want := range requiredPairs {
		if !containsSeq(got, want) {
			t.Errorf("monitorCreateArgs missing %v\n  got: %v", want, got)
		}
	}
	// The monitor must NOT be granted SYS_ADMIN or run privileged.
	for _, forbidden := range []string{"--privileged", "SYS_ADMIN"} {
		for _, a := range got {
			if a == forbidden {
				t.Errorf("monitorCreateArgs contains forbidden %q: %v", forbidden, got)
			}
		}
	}
	if got[0] != "create" {
		t.Errorf("first arg = %q, want create", got[0])
	}
}

// TestMonitorImageOverride confirms the default and the override.
func TestMonitorImageOverride(t *testing.T) {
	if got := monitorImage(Profile{}); got != DefaultMonitorImage {
		t.Errorf("default monitor image = %q, want %q", got, DefaultMonitorImage)
	}
	if got := monitorImage(Profile{MonitorImage: "myrepo/mon:1"}); got != "myrepo/mon:1" {
		t.Errorf("override monitor image = %q, want %q", got, "myrepo/mon:1")
	}
}

// TestNetworkArgsBranches asserts the sandbox network flag: --network none by
// default, and joining the monitor netns when NetworkContainer is set, with the
// rest of the hardening untouched in both branches.
func TestNetworkArgsBranches(t *testing.T) {
	none := createArgs("s", Profile{})
	if !containsSeq(none, []string{"--network", "none"}) {
		t.Errorf("default should be --network none: %v", none)
	}

	joined := createArgs("s", Profile{NetworkContainer: "meguard-egress-abc"})
	if !containsSeq(joined, []string{"--network", "container:meguard-egress-abc"}) {
		t.Errorf("egress run should join monitor netns: %v", joined)
	}
	if containsSeq(joined, []string{"--network", "none"}) {
		t.Errorf("egress run must not also pass --network none: %v", joined)
	}
	// Every other hardening flag must survive the network branch.
	for _, want := range [][]string{
		{"--cap-drop", "ALL"},
		{"--read-only"},
		{"--security-opt", "no-new-privileges"},
		{"--user", "1000:1000"},
	} {
		if !containsSeq(joined, want) {
			t.Errorf("egress run dropped hardening flag %v: %v", want, joined)
		}
	}
}
