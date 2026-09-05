package sandbox

import "testing"

// containsSeq reports whether want appears as a contiguous subsequence of got.
func containsSeq(got, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for i := 0; i+len(want) <= len(got); i++ {
		match := true
		for j := range want {
			if got[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestCreateArgsHardening is the argv contract test. It asserts that every
// required hardening flag is present in the `docker create` argv.
//
// FAILURE DIRECTION: this test FAILS if any hardening flag is removed from or
// altered in createArgs. It is the guard that keeps the lockdown from silently
// eroding. It does NOT fail when new (still-safe) flags are added.
func TestCreateArgsHardening(t *testing.T) {
	requiredPairs := [][]string{
		{"--user", "1000:1000"},
		{"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges"},
		{"--read-only"},
		{"--tmpfs", "/repo:exec"},
		{"--tmpfs", "/home/sandbox"},
		{"--tmpfs", "/tmp"},
		{"--pids-limit", "512"},
		{"--memory", "2g"},
		{"--cpus", "2"},
		{"--network", "none"},
		{"-w", "/repo"},
		{"-e", "HOME=/home/sandbox"},
	}

	// The zero-value Profile must already be fully locked down.
	got := createArgs("meguard-test", Profile{})

	for _, want := range requiredPairs {
		if !containsSeq(got, want) {
			t.Errorf("createArgs is missing required hardening flag %v\n  got: %v", want, got)
		}
	}

	if got[0] != "create" {
		t.Errorf("first arg = %q, want %q", got[0], "create")
	}

	// The image and keep-alive command must be the tail of the argv.
	tail := got[len(got)-3:]
	if !containsSeq(tail, []string{DefaultImage, "sleep", "infinity"}) {
		t.Errorf("argv tail = %v, want [%s sleep infinity]", tail, DefaultImage)
	}
}

// TestCreateArgsNetworkAlwaysNone asserts that no Profile relaxation can drop
// --network none. Network isolation is hardcoded for this slice.
func TestCreateArgsNetworkAlwaysNone(t *testing.T) {
	tests := []struct {
		name    string
		profile Profile
	}{
		{"zero value", Profile{}},
		{"custom image", Profile{Image: "python:3.12-slim"}},
		{"custom cmd", Profile{InstallCmd: []string{"pip", "install", "-r", "requirements.txt"}}},
		{"relaxed resources", Profile{Memory: "8g", CPUs: "4", PidsLimit: 4096}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createArgs("meguard-test", tt.profile)
			if !containsSeq(got, []string{"--network", "none"}) {
				t.Errorf("createArgs dropped --network none for %s: %v", tt.name, got)
			}
			if !containsSeq(got, []string{"--read-only"}) {
				t.Errorf("createArgs dropped --read-only for %s: %v", tt.name, got)
			}
		})
	}
}

// TestCreateArgsRelaxationsApply confirms that Profile fields relax the intended
// (non-security) ceilings and ecosystem values, and only those.
func TestCreateArgsRelaxationsApply(t *testing.T) {
	got := createArgs("meguard-test", Profile{
		Image:     "python:3.12-slim",
		Memory:    "8g",
		CPUs:      "4",
		PidsLimit: 4096,
	})
	for _, want := range [][]string{
		{"--memory", "8g"},
		{"--cpus", "4"},
		{"--pids-limit", "4096"},
	} {
		if !containsSeq(got, want) {
			t.Errorf("relaxation %v did not apply: %v", want, got)
		}
	}
	if got[len(got)-3] != "python:3.12-slim" {
		t.Errorf("image not applied: tail = %v", got[len(got)-3:])
	}
}
