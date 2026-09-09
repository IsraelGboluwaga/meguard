package sandbox_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/IsraelGboluwaga/meguard/internal/sandbox"
)

// TestDetectExecPlan is table-driven over repo shapes and asserts the runtime
// execution plan meguard auto-detects: a build step (Window 0, run to
// completion) when a build script exists, then the preferred long-running entry
// under the observation window. Files are written into a temp dir so detection
// exercises the same read-only filesystem inspection it uses in production.
func TestDetectExecPlan(t *testing.T) {
	const window = 3 * time.Second

	tests := []struct {
		name  string
		eco   string
		files map[string]string // path -> contents (dirs implied)
		want  []sandbox.ExecStep
	}{
		{
			name: "node build then start",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"scripts":{"build":"tsc","start":"node ."}}`,
			},
			want: []sandbox.ExecStep{
				{Label: "build", Cmd: []string{"npm", "run", "build"}},
				{Label: "start", Cmd: []string{"npm", "start"}, Window: window},
			},
		},
		{
			name: "node prefers start over dev and serve",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"scripts":{"dev":"vite","serve":"vite preview","start":"node ."}}`,
			},
			want: []sandbox.ExecStep{
				{Label: "start", Cmd: []string{"npm", "start"}, Window: window},
			},
		},
		{
			name: "node falls back to dev when no start",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"scripts":{"dev":"next dev"}}`,
			},
			want: []sandbox.ExecStep{
				{Label: "dev", Cmd: []string{"npm", "run", "dev"}, Window: window},
			},
		},
		{
			name: "node uses main when it exists and no run scripts",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"main":"server.js"}`,
				"server.js":    "console.log('hi')",
			},
			want: []sandbox.ExecStep{
				{Label: "node server.js", Cmd: []string{"node", "server.js"}, Window: window},
			},
		},
		{
			name: "node ignores main that does not exist, uses index.js",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"main":"missing.js"}`,
				"index.js":     "console.log('hi')",
			},
			want: []sandbox.ExecStep{
				{Label: "node index.js", Cmd: []string{"node", "index.js"}, Window: window},
			},
		},
		{
			name: "node build only when no runnable entry",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"scripts":{"build":"tsc","test":"jest"}}`,
			},
			want: []sandbox.ExecStep{
				{Label: "build", Cmd: []string{"npm", "run", "build"}},
			},
		},
		{
			name: "node empty scripts and no entry yields no plan",
			eco:  "node",
			files: map[string]string{
				"package.json": `{"name":"x","scripts":{"test":"jest"}}`,
			},
			want: nil,
		},
		{
			name: "node malformed package.json yields no plan",
			eco:  "node",
			files: map[string]string{
				"package.json": `{not valid json`,
			},
			want: nil,
		},
		{
			name: "python prefers main.py",
			eco:  "python",
			files: map[string]string{
				"main.py": "print('hi')",
				"app.py":  "print('hi')",
			},
			want: []sandbox.ExecStep{
				{Label: "python main.py", Cmd: []string{"python", "main.py"}, Window: window},
			},
		},
		{
			name: "python single loose script",
			eco:  "python",
			files: map[string]string{
				"solution.py": "print('hi')",
			},
			want: []sandbox.ExecStep{
				{Label: "python solution.py", Cmd: []string{"python", "solution.py"}, Window: window},
			},
		},
		{
			name: "python ambiguous multiple loose scripts yields no plan",
			eco:  "python",
			files: map[string]string{
				"one.py": "print('1')",
				"two.py": "print('2')",
			},
			want: nil,
		},
		{
			name: "unknown ecosystem yields no plan",
			eco:  "ruby",
			files: map[string]string{
				"Gemfile": "source 'x'",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for path, contents := range tt.files {
				full := filepath.Join(dir, path)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := sandbox.DetectExecPlan(dir, sandbox.Ecosystem{Name: tt.eco}, window)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetectExecPlan()\n got:  %+v\n want: %+v", got, tt.want)
			}
		})
	}
}
