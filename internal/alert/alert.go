// Package alert dispatches deduplicated, asynchronous security alerts to local
// webhooks (with optional HMAC-SHA256 signatures and AES-256-GCM encryption)
// and the Telegram Bot API.
package alert

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

type Config struct {
	WebhookURL      string
	WebhookSecret   string // optional HMAC-SHA256 signing secret
	EncryptKey      string // optional passphrase/key for AES-256-GCM payload encryption
	TelegramToken   string
	TelegramChatID  string
	TelegramBaseURL string        // defaults to "https://api.telegram.org"
	Cooldown        time.Duration // dedup window per rule+target; defaults to 30s
	MinSeverity     string        // high | medium | low; default "high"
	Client          *http.Client
	Logf            func(string, ...any)
}

type Payload struct {
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Sensor    string    `json:"sensor"`
	Severity  string    `json:"severity"`
	Action    string    `json:"action"`
	Effective string    `json:"effective"`
	Rules     []string  `json:"rules,omitempty"`
	Session   string    `json:"session,omitempty"`
	PID       int       `json:"pid,omitempty"`
	Target    string    `json:"target,omitempty"`
	Summary   string    `json:"summary"`
}

// EncryptedEnvelope wraps an AES-256-GCM encrypted Payload JSON blob.
type EncryptedEnvelope struct {
	Alg        string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Dispatcher struct {
	cfg    Config
	client *http.Client
	queue  chan Payload
	sent   atomic.Uint64

	mu       sync.Mutex
	lastSent map[string]time.Time
}

func New(cfg Config) *Dispatcher {
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.TelegramBaseURL == "" {
		cfg.TelegramBaseURL = "https://api.telegram.org"
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "high"
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	cl := cfg.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Second}
	}
	return &Dispatcher{
		cfg:      cfg,
		client:   cl,
		queue:    make(chan Payload, 128),
		lastSent: map[string]time.Time{},
	}
}

func (d *Dispatcher) Enabled() bool {
	return d.cfg.WebhookURL != "" || (d.cfg.TelegramToken != "" && d.cfg.TelegramChatID != "")
}

func (d *Dispatcher) SentCount() uint64 { return d.sent.Load() }

// Submit evaluates whether ev warrants alerting, applies cooldown dedup, and
// enqueues delivery asynchronously (non-blocking).
func (d *Dispatcher) Submit(ev event.Event) bool {
	if !d.Enabled() || !d.shouldAlert(ev) {
		return false
	}
	p := buildPayload(ev)
	dedupKey := strings.Join(p.Rules, ",") + "|" + p.Target + "|" + p.Session + "|" + p.Effective

	now := time.Now()
	d.mu.Lock()
	if prev, ok := d.lastSent[dedupKey]; ok && now.Sub(prev) < d.cfg.Cooldown {
		d.mu.Unlock()
		return false
	}
	d.lastSent[dedupKey] = now
	d.mu.Unlock()

	select {
	case d.queue <- p:
		return true
	default:
		return false
	}
}

// Run drains the alert queue until ctx is canceled.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-d.queue:
			d.deliver(ctx, p)
		}
	}
}

func (d *Dispatcher) shouldAlert(ev event.Event) bool {
	if ev.Verdict != nil {
		switch ev.Verdict.Effective {
		case "BLOCK", "SEVER", "QUARANTINE":
			return true
		}
	}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}
	return rank[ev.Severity] >= rank[d.cfg.MinSeverity] && ev.Verdict != nil && len(ev.Verdict.Rules) > 0
}

func (d *Dispatcher) deliver(ctx context.Context, p Payload) {
	var delivered bool
	if d.cfg.WebhookURL != "" {
		if err := d.sendWebhook(ctx, p); err != nil {
			d.cfg.Logf("webhook alert failed: %v", err)
		} else {
			delivered = true
		}
	}
	if d.cfg.TelegramToken != "" && d.cfg.TelegramChatID != "" {
		if err := d.sendTelegram(ctx, p); err != nil {
			d.cfg.Logf("telegram alert failed: %v", err)
		} else {
			delivered = true
		}
	}
	if delivered {
		d.sent.Add(1)
	}
}

func (d *Dispatcher) sendWebhook(ctx context.Context, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if d.cfg.EncryptKey != "" {
		env, err := EncryptPayload(body, d.cfg.EncryptKey)
		if err != nil {
			return err
		}
		if body, err = json.Marshal(env); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.cfg.WebhookSecret != "" {
		req.Header.Set("X-Sentinel-Signature", "sha256="+SignHMAC(body, d.cfg.WebhookSecret))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *Dispatcher) sendTelegram(ctx context.Context, p Payload) error {
	text := fmt.Sprintf("[Sentinel-X] %s (%s)\nAction: %s -> %s\nRules: %s\nTarget: %s\nEvent: %s",
		strings.ToUpper(p.Severity), p.Sensor, p.Action, p.Effective,
		strings.Join(p.Rules, ", "), p.Target, p.EventID)
	body, err := json.Marshal(map[string]any{
		"chat_id": d.cfg.TelegramChatID,
		"text":    text,
	})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(d.cfg.TelegramBaseURL, "/") + "/bot" + d.cfg.TelegramToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func buildPayload(ev event.Event) Payload {
	p := Payload{
		EventID:   ev.EventID,
		Timestamp: ev.Timestamp,
		Sensor:    ev.Source.Sensor,
		Severity:  ev.Severity,
		Session:   ev.Session,
		PID:       ev.PID,
		Target:    ev.Object.Resource + ":" + ev.Object.Value,
	}
	if ev.Verdict != nil {
		p.Action = ev.Verdict.Action
		p.Effective = ev.Verdict.Effective
		p.Rules = ev.Verdict.Rules
	}
	p.Summary = fmt.Sprintf("%s %s (%s)", p.Effective, p.Target, strings.Join(p.Rules, ","))
	return p
}

// SignHMAC returns lowercase hex HMAC-SHA256(body, secret).
func SignHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// EncryptPayload encrypts plaintext with AES-256-GCM using SHA-256(keyMaterial).
func EncryptPayload(plaintext []byte, keyMaterial string) (EncryptedEnvelope, error) {
	key := sha256.Sum256([]byte(keyMaterial))
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedEnvelope{}, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return EncryptedEnvelope{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedEnvelope{}, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return EncryptedEnvelope{
		Alg:        "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// DecryptPayload decrypts an EncryptedEnvelope produced by EncryptPayload.
func DecryptPayload(env EncryptedEnvelope, keyMaterial string) ([]byte, error) {
	key := sha256.Sum256([]byte(keyMaterial))
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}
