package analyze

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// pattern is one named, cheap first-pass regex signature.
type pattern struct {
	// category groups this pattern for the correlation pass (see
	// analyze.go's correlate). Multiple patterns can share a category.
	category    string
	description string
	severity    Severity
	re          *regexp.Regexp
	// scopeExt, when non-empty, restricts this pattern to files whose
	// extension (lowercase, with the leading dot) is in the list. Empty
	// means "applies to any text file".
	scopeExt []string
}

func (p pattern) appliesTo(relPath string) bool {
	if len(p.scopeExt) == 0 {
		return true
	}
	ext := strings.ToLower(filepath.Ext(relPath))
	for _, e := range p.scopeExt {
		if ext == e {
			return true
		}
	}
	return false
}

// --- Obfuscation / hidden execution -----------------------------------

// obfuscatorHexIdentRe is the fingerprint of the javascript-obfuscator tool
// used to hide payloads in most real npm supply-chain backdoors: it names
// every generated identifier _0xNNNN. Normal minifiers (terser, esbuild) do
// not use this naming scheme, so a handful of matches in one file is a
// specific, low-noise signature -- handled separately from the generic
// per-line patterns below because what matters is the REPEAT count, not a
// single match (see regexAnalyzer.Analyze).
var obfuscatorHexIdentRe = regexp.MustCompile(`_0x[0-9a-f]{4,6}`)

// obfuscatorHexIdentThreshold is how many distinct matches in one file are
// required before the obfuscator fingerprint fires. A single incidental match
// (an unrelated variable that happens to look like this) is not evidence; a
// cluster of them is the tool's actual naming convention.
const obfuscatorHexIdentThreshold = 5

var obfuscationPatterns = []pattern{
	{
		category:    "obfuscation",
		description: "classic JS packer/obfuscator signature (eval(function(p,a,c,k,e,d)))",
		severity:    Critical,
		re:          regexp.MustCompile(`eval\(function\(p,a,c,k,e,d\)`),
	},
	{
		category:    "obfuscation",
		description: "Function-constructor string-eval (builds and runs code from a string at runtime)",
		severity:    High,
		re:          regexp.MustCompile(`\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"` + "`" + `]`),
	},
	{
		category:    "obfuscation",
		description: "require stashed onto global/globalThis, a common deobfuscation-loader pattern",
		severity:    High,
		// No trailing "(" required: the stash assigns the require FUNCTION
		// itself (to be invoked later, often through a decoded name), it
		// does not need to call it on the same line.
		re: regexp.MustCompile(`\b(global|globalThis)(\[[^\]]+\]|\.\w+)\s*=\s*require\b`),
	},
	{
		category:    "obfuscation",
		description: "String.fromCharCode character-code string reconstruction",
		severity:    Medium,
		re:          regexp.MustCompile(`String\.fromCharCode`),
	},
	{
		category:    "obfuscation",
		description: "base64 decode call (atob or Buffer.from(..., 'base64'))",
		severity:    Medium,
		re:          regexp.MustCompile(`\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]`),
	},
	{
		category:    "obfuscation",
		description: "long run of escaped hex/unicode bytes, a common obfuscation technique",
		severity:    High,
		re:          regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){20,}|(?:\\u[0-9a-fA-F]{4}){10,}`),
	},
}

// --- Download-and-execute -----------------------------------------------

var downloadExecPatterns = []pattern{
	{
		category:    "download-exec",
		description: "download piped directly into a shell interpreter",
		severity:    High,
		re:          regexp.MustCompile(`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b`),
	},
	{
		category:    "download-exec",
		description: "Python shell execution (os.system or subprocess with shell=True)",
		severity:    Medium,
		re:          regexp.MustCompile(`\bos\.system\s*\(|subprocess\.(Popen|call|run)\([^)]*shell\s*=\s*True`),
	},
	{
		category:    "download-exec",
		description: "Windows living-off-the-land download-and-execute (PowerShell/certutil/mshta/regsvr32)",
		severity:    High,
		re:          regexp.MustCompile(`-EncodedCommand\b|IEX\s*\(.*DownloadString\(|certutil[^\n]*-decode|\bmshta\b|regsvr32[^\n]*\/i:`),
		scopeExt:    []string{".ps1", ".bat", ".cmd", ".vbs"},
	},
}

// --- Exfiltration channels ------------------------------------------------

var exfilChannelPatterns = []pattern{
	{
		category:    "exfil-channel",
		description: "Discord webhook URL, a common free C2/exfiltration channel",
		severity:    Medium,
		re:          regexp.MustCompile(`discord(app)?\.com/api/webhooks/`),
	},
	{
		category:    "exfil-channel",
		description: "Telegram bot API call, another common exfiltration channel",
		severity:    Medium,
		re:          regexp.MustCompile(`api\.telegram\.org/bot[^\s'"]*/(sendMessage|sendDocument)`),
	},
	{
		category:    "exfil-channel",
		description: "raw-paste/anonymous file upload host, sometimes used to exfiltrate data",
		severity:    Medium,
		re:          regexp.MustCompile(`\b(pastebin\.com/api|transfer\.sh|file\.io|anonfiles\.com)\b`),
	},
}

// --- Credential / wallet paths (standalone, weak on their own) -----------

var credentialPathPatterns = []pattern{
	{
		category:    "credential-path",
		description: "browser credential/cookie store path",
		severity:    Low,
		re:          regexp.MustCompile(`Login Data|\bCookies\b|Local State|key4\.db|logins\.json`),
	},
	{
		category:    "credential-path",
		description: "cryptocurrency wallet path",
		severity:    Low,
		re:          regexp.MustCompile(`\bExodus\b|\bElectrum\b|\bMetaMask\b|Ledger Live|wallet\.dat|\.ethereum\b|\bid\.json\b`),
	},
	{
		category:    "credential-path",
		description: "developer/cloud credential file path",
		severity:    Low,
		re:          regexp.MustCompile(`\.ssh/id_rsa|\.aws/credentials|\.docker/config\.json|\.kube/config|\.npmrc\b|\.git-credentials|\.netrc\b`),
	},
}

// --- Persistence -----------------------------------------------------------

var persistencePatterns = []pattern{
	{
		category:    "persistence",
		description: "writes a persistence mechanism (shell profile, crontab, LaunchAgents, or a Windows Run-key registry entry)",
		severity:    High,
		re:          regexp.MustCompile(`\.bash_profile|\.zshrc|crontab\s+-e|crontab\s+-l|LaunchAgents|CurrentVersion\\Run|reg\s+add[^\n]*\\Run\b`),
	},
}

// --- Recon / fingerprinting (Info alone; too common in legit telemetry) ---

var reconPatterns = []pattern{
	{
		category:    "recon",
		description: "host fingerprinting call, often used to build a victim profile or detect a sandbox/VM",
		severity:    Info,
		re:          regexp.MustCompile(`os\.userInfo\(\)|os\.hostname\(\)|\bVBOX\b|\bVMware\b|\bParallels\b`),
	},
}

// --- Bulk secrets access ----------------------------------------------------

var secretsPatterns = []pattern{
	{
		category:    "secrets",
		description: "bulk environment dump (reads the whole process environment at once, not a single named var)",
		severity:    Medium,
		re:          regexp.MustCompile(`JSON\.stringify\(process\.env\)|\{\s*\.\.\.process\.env\s*\}|Object\.entries\(process\.env\)`),
	},
}

// linePatterns is every per-line pattern regexAnalyzer applies. The
// obfuscator hex-identifier fingerprint is deliberately excluded: it needs a
// repeat-count check across the whole file, not a single-line match (see
// regexAnalyzer.Analyze).
func linePatterns() []pattern {
	var all []pattern
	all = append(all, obfuscationPatterns...)
	all = append(all, downloadExecPatterns...)
	all = append(all, exfilChannelPatterns...)
	all = append(all, credentialPathPatterns...)
	all = append(all, persistencePatterns...)
	all = append(all, reconPatterns...)
	all = append(all, secretsPatterns...)
	return all
}

// --- Whole-file co-occurrence checks ---------------------------------------

// networkCallRe matches a network-capable call in JS/TS or Python.
var networkCallRe = regexp.MustCompile(`\bfetch\s*\(|\baxios\.\w+\s*\(|\bhttps?\.request\s*\(|\bnew\s+XMLHttpRequest\b|requests\.(get|post)\s*\(`)

// downloadIndicatorRe matches a call that can pull remote content, used by
// the stage2-fetch-exec check below.
var downloadIndicatorRe = regexp.MustCompile(`\bfetch\s*\(|\baxios\.\w+\s*\(|\bhttps?\.get\s*\(|urlretrieve\s*\(|curl\s+-o\b`)

// chmodExecRe matches making a file executable or spawning a process, used by
// the stage2-fetch-exec check below.
var chmodExecRe = regexp.MustCompile(`chmod\s*\([^)]*0o?[0-7]?7[0-7][0-7]|chmod\s+\+x|child_process\.\w*[Ee]xec\w*\s*\(|subprocess\.(run|call|Popen)\s*\(`)

// secretsMarkerRe matches a reference to a secrets/credential source,
// broader than secretsPatterns above (used only for the co-occurrence check,
// not as a standalone finding, since a single process.env.FOO read is
// completely normal on its own).
var secretsMarkerRe = regexp.MustCompile(`process\.env|os\.environ|\.ssh/id_rsa|\.aws/credentials|\.npmrc|keytar|\.git-credentials|Login Data|\bCookies\b|Local State|key4\.db|logins\.json|wallet\.dat|\.ethereum\b|os\.userInfo\(\)|homedir\(\)`)

// buildToolingConfigRe matches build/lint/tooling config files that have no
// legitimate reason to make a network call: a fetch/axios call INSIDE one of
// these is itself the sinister-placement signal, independent of whether it
// is obfuscated.
var buildToolingConfigRe = regexp.MustCompile(`(?i)^(tailwind|webpack|next|postcss|jest|vite|rollup)\.config\.[jt]sx?$|^\.eslintrc(\.\w+)?$`)

func isBuildToolingConfig(relPath string) bool {
	return buildToolingConfigRe.MatchString(filepath.Base(relPath))
}

type regexAnalyzer struct{}

func (regexAnalyzer) Name() string { return "regex" }

func (regexAnalyzer) Analyze(files []ScannedFile) ([]Finding, error) {
	var findings []Finding
	patterns := linePatterns()

	for _, f := range files {
		for i, line := range f.Lines {
			for _, p := range patterns {
				if !p.appliesTo(f.RelPath) {
					continue
				}
				if loc := p.re.FindStringIndex(line); loc != nil {
					findings = append(findings, Finding{
						Analyzer: "regex",
						Category: p.category,
						Severity: p.severity,
						File:     f.RelPath,
						Line:     i + 1,
						Message:  fmt.Sprintf("matches %s", p.description),
						Snippet:  truncate(line, 160),
						Count:    1,
					})
				}
			}
		}

		findings = append(findings, obfuscatorFingerprint(f)...)
		findings = append(findings, networkCoOccurrence(f)...)
		findings = append(findings, stage2FetchExec(f)...)
	}
	return findings, nil
}

// obfuscatorFingerprint flags a file where the javascript-obfuscator hex
// identifier naming convention repeats often enough to be the tool's
// signature rather than an incidental single match.
func obfuscatorFingerprint(f ScannedFile) []Finding {
	matches := obfuscatorHexIdentRe.FindAllStringIndex(f.Content, -1)
	if len(matches) < obfuscatorHexIdentThreshold {
		return nil
	}
	line := 1 + strings.Count(f.Content[:matches[0][0]], "\n")
	return []Finding{{
		Analyzer: "regex",
		Category: "obfuscation",
		Severity: High,
		File:     f.RelPath,
		Line:     line,
		Message: fmt.Sprintf(
			"javascript-obfuscator hex-identifier naming convention (_0xNNNN) repeats %d times: the fingerprint of the tool used in most real npm supply-chain backdoors",
			len(matches),
		),
		Count: 1,
	}}
}

// networkCoOccurrence flags a network call co-occurring with a secrets
// marker anywhere in the same file (High -- the actual infostealer shape,
// wherever it is hidden), and separately flags a network call sitting inside
// a build/lint/tooling config file that has no legitimate reason to make one
// (Medium on its own; the correlate pass in analyze.go escalates it further
// if a credential-path or secrets finding also landed in the same file).
func networkCoOccurrence(f ScannedFile) []Finding {
	if !networkCallRe.MatchString(f.Content) {
		return nil
	}
	var findings []Finding
	if secretsMarkerRe.MatchString(f.Content) {
		findings = append(findings, Finding{
			Analyzer: "regex",
			Category: "network",
			Severity: High,
			File:     f.RelPath,
			Message:  "a network call and a secrets/credential marker appear in the same file: this is the shape of exfiltration, wherever it is hidden",
			Count:    1,
		})
	}
	if isBuildToolingConfig(f.RelPath) {
		findings = append(findings, Finding{
			Analyzer: "regex",
			Category: "network-config",
			Severity: Medium,
			File:     f.RelPath,
			Message:  "a network call appears in a build/lint/tooling config file, which has no legitimate reason to make one",
			Count:    1,
		})
	}
	return findings
}

// stage2FetchExec flags a file that both downloads content and makes
// something executable or spawns a process: the fetch-then-run shape of a
// stage-2 payload.
func stage2FetchExec(f ScannedFile) []Finding {
	if !downloadIndicatorRe.MatchString(f.Content) || !chmodExecRe.MatchString(f.Content) {
		return nil
	}
	return []Finding{{
		Analyzer: "regex",
		Category: "stage2",
		Severity: High,
		File:     f.RelPath,
		Message:  "a download call and a chmod/exec/spawn call appear in the same file: the fetch-then-run shape of a stage-2 payload",
		Count:    1,
	}}
}

// matchPatterns runs every line pattern against a single string (used by
// manifest.go to scan a package.json lifecycle script's content, which is a
// JSON string value rather than a file on disk).
func matchPatterns(s string) []pattern {
	var matched []pattern
	for _, p := range linePatterns() {
		if p.re.MatchString(s) {
			matched = append(matched, p)
		}
	}
	return matched
}
