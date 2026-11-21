package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

func TestWebhookEncryptedSignedAndDeduplicated(t *testing.T) {
	var (
		mu       sync.Mutex
		received [][]byte
		sigs     []string
		tgHits   int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		if strings.HasPrefix(r.URL.Path, "/bot") {
			tgHits++
		} else {
			received = append(received, b)
			sigs = append(sigs, r.Header.Get("X-Sentinel-Signature"))
		}
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := New(Config{
		WebhookURL:      srv.URL + "/hook",
		WebhookSecret:   "hmac-secret",
		EncryptKey:      "aes-passphrase",
		TelegramToken:   "12345:TEST",
		TelegramChatID:  "999",
		TelegramBaseURL: srv.URL,
		Cooldown:        5 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	ev := event.New()
	ev.Source = event.Source{Type: "agent", Sensor: "sentinel-bridge"}
	ev.Object = event.Object{Resource: "tool_call", Value: "bash"}
	ev.Severity = "high"
	ev.Session = "agent-1"
	ev.Verdict = &event.Verdict{Mode: "enforce", Action: "BLOCK", Effective: "BLOCK", Rules: []string{"tool-destructive-shell"}}

	if !d.Submit(ev) {
		t.Fatal("first submit should be accepted")
	}
	if d.Submit(ev) {
		t.Fatal("duplicate submit inside cooldown should be deduplicated")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.SentCount() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || tgHits != 1 {
		t.Fatalf("expected 1 webhook + 1 telegram hit, got webhook=%d tg=%d", len(received), tgHits)
	}
	wantSig := "sha256=" + SignHMAC(received[0], "hmac-secret")
	if sigs[0] != wantSig {
		t.Fatalf("HMAC signature mismatch: got %q want %q", sigs[0], wantSig)
	}
	var env EncryptedEnvelope
	if err := json.Unmarshal(received[0], &env); err != nil || env.Alg != "AES-256-GCM" {
		t.Fatalf("expected AES-256-GCM envelope, got %s", received[0])
	}
	plain, err := DecryptPayload(env, "aes-passphrase")
	if err != nil {
		t.Fatalf("DecryptPayload failed: %v", err)
	}
	if !strings.Contains(string(plain), "tool-destructive-shell") {
		t.Fatalf("decrypted payload missing rule id: %s", plain)
	}
}
