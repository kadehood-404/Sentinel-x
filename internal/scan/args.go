package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Flatten collects every string and number inside a decoded JSON value into
// one space-separated string, in a stable order, for pattern matching.
func Flatten(v any) string {
	var parts []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			parts = append(parts, NormalizeShellSeparators(t))
		case float64, int, int64, bool:
			parts = append(parts, fmt.Sprint(t))
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k])
			}
		}
	}
	walk(v)
	return strings.TrimSpace(collapseSpace.ReplaceAllString(strings.Join(parts, " "), " "))
}

// harmlessPaths are absolute paths that are fine for any command to touch.
var harmlessPaths = map[string]bool{
	"/dev/null": true, "/dev/stdout": true, "/dev/stderr": true, "/dev/stdin": true,
}

// ExtractPaths pulls path-looking tokens out of a command line or argument
// blob: absolute paths, ~ paths, and anything that climbs with "..".
func ExtractPaths(text string) []string {
	norm := NormalizeShellSeparators(text)
	fields := strings.FieldsFunc(norm, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '"', '\'', '=', ';', '|', '&', '<', '>', '(', ')', ',':
			return true
		}
		return false
	})
	var out []string
	seen := map[string]bool{}
	for _, f := range fields {
		if strings.Contains(f, "://") || harmlessPaths[f] {
			continue
		}
		isPath := strings.HasPrefix(f, "/") || strings.HasPrefix(f, "~") ||
			strings.HasPrefix(f, "../") || f == ".." || strings.Contains(f, "/../") ||
			strings.HasSuffix(f, "/..")
		if isPath && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
