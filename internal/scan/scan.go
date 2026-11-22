// Package scan finds secrets, PII and prompt-injection phrasing in text.
//
// These are deterministic pattern matchers, not a model. They are fast and
// explainable, and they are wrong sometimes: a security blog post quoting
// "ignore previous instructions" will trip the injection detector. That is
// why every finding carries a name and a confidence, and why Sentinel-X
// defaults to observe mode.
//
// Findings never contain the matched text. Logging a leaked secret into the
// audit ledger would be its own leak.
package scan

import (
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	Secret    Kind = "secret"
	PII       Kind = "pii"
	Injection Kind = "injection"
)

type Finding struct {
	Kind       Kind    `json:"kind"`
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
	Start      int     `json:"-"`
	End        int     `json:"-"`
}

type pattern struct {
	kind     Kind
	name     string
	re       *regexp.Regexp
	weight   float64
	validate func(string) bool
}

func p(kind Kind, name, expr string, weight float64) pattern {
	return pattern{kind: kind, name: name, re: regexp.MustCompile(expr), weight: weight}
}

var (
	ifsExprRe     = regexp.MustCompile(`\$\{IFS\}|\$IFS\b`)
	collapseSpace = regexp.MustCompile(`\s+`)
)

// NormalizeShellSeparators expands ${IFS} / $IFS separator bypasses and collapses
// repeated whitespace into single spaces so lexical variants match deterministically.
func NormalizeShellSeparators(text string) string {
	if text == "" {
		return ""
	}
	replaced := ifsExprRe.ReplaceAllString(text, " ")
	return strings.TrimSpace(collapseSpace.ReplaceAllString(replaced, " "))
}

var patterns = []pattern{
	// Secrets.
	p(Secret, "aws_access_key", `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, 1),
	p(Secret, "github_token", `\bgh[pousr]_[A-Za-z0-9]{36,}\b`, 1),
	p(Secret, "github_fine_grained_pat", `\bgithub_pat_[A-Za-z0-9_]{50,}\b`, 1),
	p(Secret, "slack_token", `\bxox[baprs]-[A-Za-z0-9-]{10,}\b`, 1),
	p(Secret, "api_key_sk", `\bsk-[A-Za-z0-9_-]{20,}\b`, 1),
	p(Secret, "telegram_bot_token", `\b\d{8,10}:[A-Za-z0-9_-]{35}\b`, 1),
	p(Secret, "jwt", `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, 1),
	p(Secret, "private_key_block", `-----BEGIN [A-Z ]*PRIVATE KEY-----`, 1),
	p(Secret, "credential_assignment",
		`(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|auth)\b["']?\s*[:=]\s*["']?[A-Za-z0-9/+_\-.=]{16,}`, 1),

	// PII.
	p(PII, "email", `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, 1),
	p(PII, "us_ssn", `\b\d{3}-\d{2}-\d{4}\b`, 1),
	p(PII, "us_phone", `\b(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b`, 1),
	{kind: PII, name: "credit_card", re: regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`), weight: 1, validate: luhn},

	// Prompt injection phrasing. Weights combine: 1 - prod(1 - w).
	p(Injection, "ignore_previous",
		`(?i)\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)`, 0.85),
	p(Injection, "disregard_instructions",
		`(?i)\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?)`, 0.85),
	p(Injection, "forget_instructions",
		`(?i)\bforget\s+(?:everything|all|your)\s+(?:you|instructions|previous|prior|rules)`, 0.6),
	p(Injection, "reveal_system_prompt",
		`(?i)\b(?:reveal|show|print|repeat|output|leak)\s+(?:me\s+)?(?:your|the)\s+(?:hidden\s+|secret\s+)?(?:system\s+prompt|initial\s+instructions|instructions)`, 0.8),
	p(Injection, "persona_override",
		`(?i)\byou\s+are\s+now\s+(?:in\s+)?(?:dan|developer\s+mode|jailbroken|an?\s+unrestricted)`, 0.8),
	p(Injection, "jailbreak_terms",
		`(?i)\b(?:do\s+anything\s+now|jailbreak(?:ed)?|developer\s+mode\s+enabled)\b`, 0.5),
	p(Injection, "chat_template_tokens",
		`(?i)<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<<SYS>>`, 0.7),
	p(Injection, "new_instructions",
		`(?i)\bnew\s+(?:system\s+)?instructions?\s*:`, 0.5),
	p(Injection, "exfil_to_url",
		`(?i)\b(?:send|post|upload|exfiltrate|forward)\b.{0,40}\b(?:to|at)\s+https?://`, 0.4),
}

// Scan returns all findings in text, ordered by position.
func Scan(text string) []Finding {
	normalized := NormalizeShellSeparators(text)
	var out []Finding
	for _, pt := range patterns {
		for _, m := range pt.re.FindAllStringIndex(normalized, -1) {
			if pt.validate != nil && !pt.validate(normalized[m[0]:m[1]]) {
				continue
			}
			out = append(out, Finding{Kind: pt.kind, Name: pt.name, Confidence: pt.weight, Start: m[0], End: m[1]})
		}
	}

	// Several weak injection signals add up to one strong one.
	miss := 1.0
	seen := map[string]bool{}
	for _, f := range out {
		if f.Kind == Injection && !seen[f.Name] {
			seen[f.Name] = true
			miss *= 1 - f.Confidence
		}
	}
	if len(seen) > 0 {
		combined := 1 - miss
		for i := range out {
			if out[i].Kind == Injection {
				out[i].Confidence = combined
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// Redact replaces secret and PII matches with [REDACTED:name]. Injection
// findings are left alone: they are evidence, not data to hide.
func Redact(text string, findings []Finding) string {
	var spans []Finding
	for _, f := range findings {
		if f.Kind == Secret || f.Kind == PII {
			spans = append(spans, f)
		}
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })

	var b strings.Builder
	pos := 0
	for _, f := range spans {
		if f.Start < pos { // overlaps something already redacted
			if f.End > pos {
				pos = f.End
			}
			continue
		}
		b.WriteString(text[pos:f.Start])
		b.WriteString("[REDACTED:" + f.Name + "]")
		pos = f.End
	}
	b.WriteString(text[pos:])
	return b.String()
}

// RedactText scans text and redacts it in one step.
func RedactText(text string) string { return Redact(text, Scan(text)) }

func luhn(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}
