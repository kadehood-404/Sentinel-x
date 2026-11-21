package scan

import (
	"math"
	"regexp"
	"strings"
)

const Anomaly Kind = "anomaly"

var (
	hexLabelRe    = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)
	base32LabelRe = regexp.MustCompile(`^[A-Za-z2-7]{28,}=*$`)
	domainTokenRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]{1,63}\.){2,}[a-zA-Z]{2,24}\b`)
)

// ShannonEntropy returns the Shannon entropy in bits per byte of s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// ScanDomain evaluates a hostname/FQDN for DNS tunneling and exfiltration signals:
// high-entropy subdomains, abnormally long labels, deep nesting, or hex/base32 encoding.
func ScanDomain(domain string) []Finding {
	d := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	if d == "" || !strings.Contains(d, ".") {
		return nil
	}
	labels := strings.Split(d, ".")
	if len(labels) < 3 {
		// Apex/two-label domains like example.com are rarely tunneling carriers.
		if len(d) >= 120 {
			return []Finding{{Kind: Anomaly, Name: "dns_long_domain", Confidence: 0.7}}
		}
		return nil
	}

	var out []Finding
	if len(d) >= 120 {
		out = append(out, Finding{Kind: Anomaly, Name: "dns_long_domain", Confidence: 0.75})
	}
	if len(labels) >= 6 {
		out = append(out, Finding{Kind: Anomaly, Name: "dns_deep_subdomain", Confidence: 0.6})
	}

	// Inspect subdomain labels (exclude TLD + registrable apex).
	subLabels := labels[:len(labels)-2]
	var maxEnt float64
	var longLabel, encodedLabel bool
	for _, lbl := range subLabels {
		if len(lbl) >= 48 {
			longLabel = true
		}
		if hexLabelRe.MatchString(lbl) || base32LabelRe.MatchString(lbl) {
			encodedLabel = true
		}
		if len(lbl) >= 16 {
			if e := ShannonEntropy(lbl); e > maxEnt {
				maxEnt = e
			}
		}
	}
	if longLabel {
		out = append(out, Finding{Kind: Anomaly, Name: "dns_long_label", Confidence: 0.8})
	}
	if encodedLabel {
		out = append(out, Finding{Kind: Anomaly, Name: "dns_encoded_subdomain", Confidence: 0.85})
	}
	if maxEnt >= 3.6 {
		conf := 0.75
		if maxEnt >= 4.0 {
			conf = 0.9
		}
		out = append(out, Finding{Kind: Anomaly, Name: "dns_high_entropy", Confidence: conf})
	}
	return out
}

// ExtractDomains extracts candidate multi-label domains from command lines or argument text.
func ExtractDomains(text string) []string {
	matches := domainTokenRe.FindAllString(text, -1)
	seen := make(map[string]bool, len(matches))
	var out []string
	for _, m := range matches {
		low := strings.ToLower(m)
		if !seen[low] {
			seen[low] = true
			out = append(out, low)
		}
	}
	return out
}
