// Package miniyaml parses the small YAML subset Sentinel-X rulebooks use.
//
// Why not a real YAML library: this is a security tool that ships as a single
// static binary, and a rulebook is a small, flat, boring document. Zero
// third-party dependencies means zero supply chain to audit.
//
// Supported: nested maps, lists ("- item", "- key: value" maps), inline lists
// ([a, b]), plain / 'single' / "double" quoted scalars, bools, ints, floats,
// null, and # comments. Not supported: anchors, multi-line scalars, tags,
// inline maps, multiple documents. Anything unsupported fails loudly rather
// than being half-understood.
//
// Values come back as map[string]any, []any, string, bool, int64, float64, nil.
package miniyaml

import (
	"fmt"
	"strconv"
	"strings"
)

type line struct {
	indent int
	text   string
	no     int
}

type parser struct {
	lines []line
	i     int
}

// Parse parses a document.
func Parse(src []byte) (any, error) {
	lines, err := prepare(string(src))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	p := &parser{lines: lines}
	v, err := p.block(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		l := p.lines[p.i]
		return nil, fmt.Errorf("line %d: unexpected indentation or content %q", l.no, l.text)
	}
	return v, nil
}

func prepare(src string) ([]line, error) {
	var out []line
	for n, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		if strings.Contains(raw, "\t") && strings.TrimLeft(raw, " ") != strings.TrimLeft(raw, " \t") {
			return nil, fmt.Errorf("line %d: tabs are not allowed for indentation", n+1)
		}
		text := strings.TrimRight(stripComment(raw), " \t")
		if strings.TrimSpace(text) == "" {
			continue
		}
		trimmed := strings.TrimLeft(text, " ")
		out = append(out, line{indent: len(text) - len(trimmed), text: trimmed, no: n + 1})
	}
	return out, nil
}

// stripComment removes a trailing "# ..." comment that is outside quotes.
func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			// A quote only opens a string at the start of a value.
			if i == 0 || s[i-1] == ' ' || s[i-1] == '[' || s[i-1] == ',' {
				q = c
			}
		case c == '#':
			if i == 0 || s[i-1] == ' ' {
				return s[:i]
			}
		}
	}
	return s
}

func isDash(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *parser) block(indent int) (any, error) {
	if p.i >= len(p.lines) {
		return nil, nil
	}
	if isDash(p.lines[p.i].text) {
		return p.list(indent)
	}
	return p.mapping(indent)
}

func (p *parser) list(indent int) ([]any, error) {
	out := []any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent || !isDash(l.text) {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: bad indentation in list", l.no)
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		switch {
		case rest == "":
			p.i++
			if p.i < len(p.lines) && p.lines[p.i].indent > indent {
				v, err := p.block(p.lines[p.i].indent)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
		case looksLikeKV(rest):
			// "- key: value" starts a map whose keys line up after the dash.
			off := len(l.text) - len(strings.TrimLeft(l.text[1:], " "))
			p.lines[p.i] = line{indent: indent + off, text: rest, no: l.no}
			v, err := p.mapping(indent + off)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			v, err := scalar(rest, l.no)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			p.i++
		}
	}
	return out, nil
}

func (p *parser) mapping(indent int) (map[string]any, error) {
	out := map[string]any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: bad indentation", l.no)
		}
		if isDash(l.text) {
			break
		}
		key, val, ok := splitKV(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\", got %q", l.no, l.text)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", l.no, key)
		}
		p.i++
		if val != "" {
			v, err := scalar(val, l.no)
			if err != nil {
				return nil, err
			}
			out[key] = v
			continue
		}
		switch {
		case p.i < len(p.lines) && p.lines[p.i].indent > indent:
			v, err := p.block(p.lines[p.i].indent)
			if err != nil {
				return nil, err
			}
			out[key] = v
		case p.i < len(p.lines) && p.lines[p.i].indent == indent && isDash(p.lines[p.i].text):
			v, err := p.list(indent) // list at the same indent as its key
			if err != nil {
				return nil, err
			}
			out[key] = v
		default:
			out[key] = nil
		}
	}
	return out, nil
}

func looksLikeKV(s string) bool {
	if s == "" || s[0] == '\'' || s[0] == '"' || s[0] == '[' {
		return false
	}
	_, _, ok := splitKV(s)
	return ok
}

func splitKV(s string) (key, val string, ok bool) {
	if strings.HasSuffix(s, ":") {
		return strings.TrimSpace(s[:len(s)-1]), "", true
	}
	if i := strings.Index(s, ": "); i > 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), true
	}
	return "", "", false
}

func scalar(s string, no int) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return nil, nil
	case s[0] == '"':
		u, err := strconv.Unquote(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad double-quoted string %s", no, s)
		}
		return u, nil
	case s[0] == '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return nil, fmt.Errorf("line %d: unterminated single-quoted string", no)
		}
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
	case s[0] == '[':
		return inlineList(s, no)
	case s[0] == '{':
		return nil, fmt.Errorf("line %d: inline maps are not supported", no)
	case s[0] == '&' || s[0] == '*' || s[0] == '!' || s[0] == '|' || s[0] == '>':
		return nil, fmt.Errorf("line %d: anchors, tags and block scalars are not supported", no)
	}
	switch strings.ToLower(s) {
	case "null", "~":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return s, nil
}

func inlineList(s string, no int) ([]any, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("line %d: unterminated inline list", no)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := []any{}
	if inner == "" {
		return out, nil
	}
	var parts []string
	var q byte
	start := 0
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case q != 0:
			if c == '\\' && q == '"' {
				i++
			} else if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == ',':
			parts = append(parts, inner[start:i])
			start = i + 1
		}
	}
	if q != 0 {
		return nil, fmt.Errorf("line %d: unterminated quote in inline list", no)
	}
	parts = append(parts, inner[start:])
	for _, part := range parts {
		v, err := scalar(part, no)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
