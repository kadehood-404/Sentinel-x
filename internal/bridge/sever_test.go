package bridge

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func TestSeverSessionAbortsInFlightStreamAndRevokesToken(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte("chunk1\n"))
			f.Flush()
		}
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	up, _ := url.Parse(upstream.URL)

	rs, err := policy.Load("../../rules/bridge")
	if err != nil {
		t.Fatal(err)
	}
	br := New(Config{
		Upstream: up, Engine: policy.NewEngine(policy.Enforce, rs),
		Workspace: "/work/agent", Hostname: "test",
	})
	srv := httptest.NewServer(br)
	defer srv.Close()

	// Mint a daemon session token via /v1/session.
	sessResp, err := http.Post(srv.URL+"/v1/session", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(sessResp.Body).Decode(&minted); err != nil || minted.Session == "" {
		sessResp.Body.Close()
		t.Fatalf("failed to mint session: status=%d err=%v", sessResp.StatusCode, err)
	}
	sessResp.Body.Close()

	// Start a streaming request authenticated with the minted Bearer token.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate", strings.NewReader(`{"model":"m","prompt":"stream"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+minted.Session)

	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- err
			return
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		done <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream did not start")
	}

	// Sever the session -> must cancel the in-flight upstream stream!
	cut := br.SeverSession(minted.Session)
	if cut != 1 {
		t.Fatalf("SeverSession cut=%d, want 1", cut)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream context was not canceled on SeverSession")
	}
	<-done

	// Subsequent /v1/check and proxy calls with the revoked token must be denied.
	checkReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/check",
		strings.NewReader(`{"tool":"read_file","args":{"path":"src/a.go"}}`))
	checkReq.Header.Set("Authorization", "Bearer "+minted.Session)
	resp, err := http.DefaultClient.Do(checkReq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"decision":"deny"`) || !strings.Contains(string(b), "session-severed") {
		t.Fatalf("expected revoked session check to deny, got %s", b)
	}

	proxyReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/generate", strings.NewReader(`{"model":"m","prompt":"after"}`))
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set("Authorization", "Bearer "+minted.Session)
	proxyResp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		t.Fatal(err)
	}
	proxyResp.Body.Close()
	if proxyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected revoked session proxy call to return 403, got %d", proxyResp.StatusCode)
	}
}
