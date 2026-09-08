package analyze

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// longLineThreshold is the line length (in characters) above which a line is
// considered for entropy scoring at all. This is the generalizable version of
// "a 5,398-character line pushed off the right edge of the editor": it
// catches an obfuscated payload appended after legitimate code on the same
// physical line, in ANY text file, without hardcoding a filename.
const longLineThreshold = 300

// veryLongLineThreshold escalates severity on length alone, even at
// middling entropy, since a line this long is already far outside anything a
// human would hand-write.
const veryLongLineThreshold = 1000

// highEntropyThreshold (bits per character) is where a line reads as dense,
// packed data (base64/minified-and-mangled) rather than prose or normal code
// punctuation. Empirically, byte-level Shannon entropy of ordinary English
// prose runs close to 4.3-4.4 bits/char and base64 blobs run 4.9-6.0; this
// sits above the prose band so a long natural-language line does not
// misfire, while base64/packed data still clears it.
const highEntropyThreshold = 4.8

// svgScriptTagRe matches an SVG <script> tag (case-insensitive). Its
// presence is what makes an SVG executable rather than static vector
// graphics (see isSVGPath's exclusion below and the doc comment on it).
var svgScriptTagRe = regexp.MustCompile(`(?i)<script[\s>]`)

type entropyAnalyzer struct{}

func (entropyAnalyzer) Name() string { return "entropy" }

func (entropyAnalyzer) Analyze(files []ScannedFile) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if isMinifiedOrVendorPath(f.RelPath) {
			continue
		}
		// isSVGPath's exclusion only holds for an SVG that is actually inert:
		// one that carries a <script> tag is executable, so it loses the
		// exclusion and gets the same long-line/entropy scrutiny as any other
		// code (regex.go's signature checks already scan .svg content
		// unconditionally regardless of this; this only affects the entropy
		// heuristic). A script-carrying SVG is itself unusual enough that
		// scrutinizing its other long lines too, not just the script, is the
		// conservative choice.
		if isSVGPath(f.RelPath) && !svgScriptTagRe.MatchString(f.Content) {
			continue
		}
		for i, line := range f.Lines {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) <= longLineThreshold {
				continue
			}
			entropy := shannonEntropy(trimmed)
			sev := Medium
			if entropy >= highEntropyThreshold || len(trimmed) > veryLongLineThreshold {
				sev = High
			}
			findings = append(findings, Finding{
				Analyzer: "entropy",
				Category: "entropy",
				Severity: sev,
				File:     f.RelPath,
				Line:     i + 1,
				Message: fmt.Sprintf(
					"abnormally long line (%d chars, entropy %.1f bits/char): possible obfuscated or hidden payload appended off-screen",
					len(trimmed), entropy,
				),
				Snippet: truncate(trimmed, 120),
				Count:   1,
			})
		}
	}
	return findings, nil
}

// shannonEntropy returns s's Shannon entropy in bits per character (byte-wise
// over s's bytes). Higher values mean more uniformly distributed bytes,
// characteristic of base64/hex blobs and packed/compressed data; prose and
// normal source code score lower due to repeated common characters.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}
