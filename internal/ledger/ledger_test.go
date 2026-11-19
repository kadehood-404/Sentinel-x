package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fill(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < n; i++ {
		if _, err := l.Append(map[string]any{"i": i, "note": "a<b&c"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifiesAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	fill(t, path, 3)
	fill(t, path, 2) // reopen must continue the same chain
	n, err := Verify(path)
	if err != nil || n != 5 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	fill(t, path, 4)
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	mutate := map[string]func() string{
		"edited data": func() string { return strings.Replace(string(raw), `"i":1`, `"i":9`, 1) },
		"deleted line": func() string {
			return strings.Join(append(append([]string{}, lines[:1]...), lines[2:]...), "\n") + "\n"
		},
		"swapped lines": func() string { return strings.Join([]string{lines[0], lines[2], lines[1], lines[3]}, "\n") + "\n" },
	}
	for name, f := range mutate {
		p := filepath.Join(t.TempDir(), "t.jsonl")
		os.WriteFile(p, []byte(f()), 0o600)
		if _, err := Verify(p); err == nil {
			t.Errorf("%s: tampering not detected", name)
		}
	}
}

func TestOpenRefusesBrokenLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.jsonl")
	fill(t, path, 2)
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(raw), `"i":0`, `"i":7`, 1)), 0o600)
	if _, err := Open(path); err == nil {
		t.Fatal("appending to a tampered ledger would launder the tampering; Open must refuse")
	}
}
