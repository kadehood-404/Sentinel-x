// sentinel-bridge sits in front of a local LLM endpoint and an agent's tool
// runner. See internal/bridge for what it does.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/bridge"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func main() {
	var (
		listen   = flag.String("listen", "127.0.0.1:11435", "address to listen on (loopback only unless -allow-nonlocal)")
		upstream = flag.String("upstream", "http://127.0.0.1:11434", "model endpoint to protect (Ollama / OpenAI-compatible)")
		rules    = flag.String("rules", "rules/bridge", "directory of YAML rulebooks (hot-reloaded)")
		ledgerP  = flag.String("ledger", "sentinel-ledger.jsonl", "append-only audit ledger")
		modeS    = flag.String("mode", "observe", "observe (log only, never touch traffic) or enforce")
		ws       = flag.String("workspace", "", "default agent workspace for /v1/check (default: current directory)")
		nonlocal = flag.Bool("allow-nonlocal", false, "allow listening on a non-loopback address (no auth is provided!)")
	)
	flag.Parse()
	logger := log.New(os.Stderr, "sentinel-bridge: ", log.LstdFlags)

	loop, err := bridge.IsLoopback(*listen)
	if err != nil {
		logger.Fatal(err)
	}
	if !loop && !*nonlocal {
		logger.Fatalf("refusing to listen on %s: this API has no authentication. Use a loopback address, or pass -allow-nonlocal if you really mean it", *listen)
	}
	mode, err := policy.ParseMode(*modeS)
	if err != nil {
		logger.Fatal(err)
	}
	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		logger.Fatalf("bad -upstream %q", *upstream)
	}
	if *ws == "" {
		if *ws, err = os.Getwd(); err != nil {
			logger.Fatal(err)
		}
	}

	rs, err := policy.Load(*rules)
	if err != nil {
		logger.Fatalf("rules: %v", err)
	}
	eng := policy.NewEngine(mode, rs)

	led, err := ledger.Open(*ledgerP)
	if err != nil {
		logger.Fatalf("ledger: %v", err)
	}
	defer led.Close()

	host, _ := os.Hostname()
	srv := bridge.New(bridge.Config{
		Upstream: up, Engine: eng, Ledger: led, Workspace: *ws, Hostname: host, Logf: logger.Printf,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go policy.Watch(ctx, *rules, eng, 2*time.Second, logger.Printf)

	hs := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()

	logger.Printf("mode=%s listen=%s upstream=%s rules=%d (v%s) ledger=%s",
		mode, *listen, *upstream, len(rs.Rules), rs.Signature, *ledgerP)
	if mode == policy.Observe {
		logger.Printf("observe mode: traffic is forwarded untouched; verdicts are only logged. Use -mode enforce to apply them.")
	}
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
