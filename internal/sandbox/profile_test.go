package sandbox

import (
	"reflect"
	"testing"
)

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
