package sandbox

import (
	"reflect"
	"testing"
)

// TestDefaultImageIsSupportedNodeLTS pins the default image to a Node release
// that is still in support. It exists so a future edit cannot silently revert
// the default to an end-of-life base (Node 20 reached EOL, which was the reason
// for the bump). Update it deliberately when the LTS baseline moves.
func TestDefaultImageIsSupportedNodeLTS(t *testing.T) {
	const want = "node:22-slim"
	if DefaultImage != want {
		t.Errorf("DefaultImage = %q, want %q (a supported Node LTS)", DefaultImage, want)
	}
}

// TestProfileNormalize is a table-driven test of the zero-value-is-safe default
// filling. It asserts that empty fields become the locked-down defaults and set
// fields are preserved.
func TestProfileNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   Profile
		want Profile
	}{
		{
			name: "zero value gets all defaults",
			in:   Profile{},
			want: Profile{
				Image:      DefaultImage,
				InstallCmd: DefaultInstallCmd(),
				Memory:     DefaultMemory,
				CPUs:       DefaultCPUs,
				PidsLimit:  DefaultPidsLimit,
			},
		},
		{
			name: "set fields are preserved",
			in: Profile{
				Image:      "python:3.12-slim",
				InstallCmd: []string{"pip", "install", "."},
				Memory:     "8g",
				CPUs:       "4",
				PidsLimit:  4096,
			},
			want: Profile{
				Image:      "python:3.12-slim",
				InstallCmd: []string{"pip", "install", "."},
				Memory:     "8g",
				CPUs:       "4",
				PidsLimit:  4096,
			},
		},
		{
			name: "partial profile fills only the gaps",
			in:   Profile{Image: "golang:1.24"},
			want: Profile{
				Image:      "golang:1.24",
				InstallCmd: DefaultInstallCmd(),
				Memory:     DefaultMemory,
				CPUs:       DefaultCPUs,
				PidsLimit:  DefaultPidsLimit,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.Normalize()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Normalize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
