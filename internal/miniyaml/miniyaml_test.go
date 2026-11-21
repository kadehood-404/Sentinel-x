package miniyaml

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRulebookShapes(t *testing.T) {
	src := `
# comment
rules:
  - id: a   # trailing comment
    n: 3
    f: 0.5
    ok: true
    nothing: null
    tools: [shell, "ba sh", 'x, y']
    re: '(?i)\.ssh/|a: b # not a comment'
    match:
      finding: [secret]
      repeat:
        count: 5
        window: 60
  - id: b
    list:
      - one
      - two
`
	got, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	rules := got.(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(rules))
	}
	a := rules[0].(map[string]any)
	want := map[string]any{
		"id": "a", "n": int64(3), "f": 0.5, "ok": true, "nothing": nil,
		"tools": []any{"shell", "ba sh", "x, y"},
		"re":    `(?i)\.ssh/|a: b # not a comment`,
		"match": map[string]any{
			"finding": []any{"secret"},
			"repeat":  map[string]any{"count": int64(5), "window": int64(60)},
		},
	}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("rule a mismatch:\n got %#v\nwant %#v", a, want)
	}
	b := rules[1].(map[string]any)
	if !reflect.DeepEqual(b["list"], []any{"one", "two"}) {
		t.Fatalf("bad nested list: %#v", b["list"])
	}
}

func TestParseTopLevelList(t *testing.T) {
	got, err := Parse([]byte("- a\n- b\n"))
	if err != nil || !reflect.DeepEqual(got, []any{"a", "b"}) {
		t.Fatalf("got %#v, %v", got, err)
	}
}

func TestParseRejectsUnsupportedAndBroken(t *testing.T) {
	bad := map[string]string{
		"tab indent":    "a:\n\tb: 1\n",
		"duplicate key": "a: 1\na: 2\n",
		"inline map":    "a: {b: 1}\n",
		"anchor":        "a: &x 1\n",
		"block scalar":  "a: |\n  text\n",
		"bad indent":    "a: 1\n   b: 2\n",
		"unterminated":  "a: 'oops\n",
		"no colon":      "justtext\nmore: 1\n",
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestEmptyDocument(t *testing.T) {
	got, err := Parse([]byte("\n# only comments\n\n"))
	if err != nil || got != nil {
		t.Fatalf("got %#v, %v", got, err)
	}
}

func TestErrorsNameTheLine(t *testing.T) {
	_, err := Parse([]byte("a: 1\nb: {x}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("want error mentioning line 2, got %v", err)
	}
}
