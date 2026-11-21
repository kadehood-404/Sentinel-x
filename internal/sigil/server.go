//go:build linux

package sigil

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kadehood-404/sentinel-x/internal/event"
	"github.com/kadehood-404/sentinel-x/internal/ledger"
)

// Handlers wires sigil-sync IPC events into sentinel-core, sentinel-hammer,
// and sentinel-bridge.
type Handlers struct {
	OnThreatSignal func(sig ThreatSignalPayload, source string, peer PeerInfo)
	OnControlCmd   func(cmd ControlCmdPayload, peer PeerInfo) (ok bool, msg string, snap *StateSnapshot)
	Snapshot       func() StateSnapshot
}

type ServerConfig struct {
	SocketPath string
	Hostname   string
	Ledger     *ledger.Ledger // every control_cmd is appended here
	Handlers   Handlers
	Logf       func(string, ...any)
}

type peerConn struct {
	conn   net.Conn
	info   PeerInfo
	subs   map[string]bool
	sendCh chan []byte
	mu     sync.Mutex
}

// Server hosts the Unix Domain Socket listener (sigil.sock) with non-blocking
// fan-out and mandatory hash-chained ledger auditing of all control_cmds.
type Server struct {
	cfg      ServerConfig
	ln       net.Listener
	mu       sync.RWMutex
	peers    map[*peerConn]bool
	dropped  atomic.Uint64
	stopOnce sync.Once
}

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath()
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		return nil, err
	}
	// Remove stale socket file if present.
	if st, err := os.Lstat(cfg.SocketPath); err == nil {
		if st.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(cfg.SocketPath)
		} else {
			return nil, fmt.Errorf("%s exists and is not a Unix socket", cfg.SocketPath)
		}
	}
	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return &Server{
		cfg:   cfg,
		ln:    ln,
		peers: make(map[*peerConn]bool),
	}, nil
}

func (s *Server) SocketPath() string { return s.cfg.SocketPath }
func (s *Server) Dropped() uint64    { return s.dropped.Load() }

// Peers returns currently connected Unix socket peers.
func (s *Server) Peers() []PeerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerInfo, 0, len(s.peers))
	for p := range s.peers {
		p.mu.Lock()
		info := p.info
		p.mu.Unlock()
		out = append(out, info)
	}
	return out
}

// Serve accepts Unix socket connections until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.cfg.Logf("sigil accept error: %v", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

// Close shuts down the listener and removes the socket file.
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		if s.ln != nil {
			_ = s.ln.Close()
		}
		s.mu.Lock()
		for p := range s.peers {
			_ = p.conn.Close()
		}
		s.mu.Unlock()
		_ = os.Remove(s.cfg.SocketPath)
	})
}

// Broadcast sends env to all peers subscribed to env.Type without blocking.
func (s *Server) Broadcast(env Envelope) {
	line, err := json.Marshal(env)
	if err != nil {
		return
	}
	line = append(line, '\n')

	s.mu.RLock()
	targets := make([]*peerConn, 0, len(s.peers))
	for p := range s.peers {
		p.mu.Lock()
		want := p.subs[env.Type] || p.subs["*"]
		p.mu.Unlock()
		if want {
			targets = append(targets, p)
		}
	}
	s.mu.RUnlock()

	for _, p := range targets {
		select {
		case p.sendCh <- line:
		default:
			s.dropped.Add(1)
		}
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	pid, uid := readPeerCred(conn)
	p := &peerConn{
		conn: conn,
		info: PeerInfo{
			Source:      "unknown",
			PID:         pid,
			UID:         uid,
			ConnectedAt: time.Now().UTC(),
		},
		subs:   map[string]bool{},
		sendCh: make(chan []byte, 64),
	}

	s.mu.Lock()
	s.peers[p] = true
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-p.sendCh:
				if !ok {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if _, err := conn.Write(msg); err != nil {
					return
				}
			}
		}
	}()

	defer func() {
		s.mu.Lock()
		delete(s.peers, p)
		s.mu.Unlock()
		close(p.sendCh)
		_ = conn.Close()
		<-done
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 8192), MaxFrameBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		env, err := DecodeFrame([]byte(line))
		if err != nil {
			s.sendAck(p, "", false, "bad frame: "+err.Error(), nil)
			continue
		}
		if env.Source != "" {
			p.mu.Lock()
			p.info.Source = env.Source
			p.mu.Unlock()
		}
		s.dispatch(p, env)
	}
}

func (s *Server) dispatch(p *peerConn, env Envelope) {
	p.mu.Lock()
	peer := p.info
	p.mu.Unlock()

	switch env.Type {
	case TypeHello, TypeSubscribe:
		var hp HelloPayload
		_ = json.Unmarshal(env.Payload, &hp)
		p.mu.Lock()
		for _, sub := range hp.Subscriptions {
			p.subs[sub] = true
		}
		p.mu.Unlock()
		if hp.WantSnapshot && s.cfg.Handlers.Snapshot != nil {
			snap := s.cfg.Handlers.Snapshot()
			if se, err := NewEnvelope("sentinel-x", TypeStateSnapshot, snap); err == nil {
				s.sendEnvelope(p, se)
			}
		}

	case TypeThreatSignal:
		var sig ThreatSignalPayload
		if err := json.Unmarshal(env.Payload, &sig); err != nil {
			s.sendAck(p, env.ID, false, "bad threat_signal payload: "+err.Error(), nil)
			return
		}
		if s.cfg.Handlers.OnThreatSignal != nil {
			s.cfg.Handlers.OnThreatSignal(sig, env.Source, peer)
		}
		s.sendAck(p, env.ID, true, "threat_signal processed", nil)

	case TypeControlCmd:
		var cmd ControlCmdPayload
		if err := json.Unmarshal(env.Payload, &cmd); err != nil {
			s.auditControlCmd(cmd, peer, env.ID, false, "bad control_cmd JSON: "+err.Error())
			s.sendAck(p, env.ID, false, "bad control_cmd JSON: "+err.Error(), nil)
			return
		}
		ok := false
		msg := "no control handler configured"
		var snap *StateSnapshot
		if s.cfg.Handlers.OnControlCmd != nil {
			ok, msg, snap = s.cfg.Handlers.OnControlCmd(cmd, peer)
		}
		// Mandatory: every control_cmd MUST be recorded in the hash-chained ledger.
		s.auditControlCmd(cmd, peer, env.ID, ok, msg)
		s.sendAck(p, env.ID, ok, msg, snap)

	default:
		s.sendAck(p, env.ID, false, "unsupported message type "+env.Type, nil)
	}
}

func (s *Server) auditControlCmd(cmd ControlCmdPayload, peer PeerInfo, envID string, ok bool, msg string) {
	if s.cfg.Ledger == nil {
		return
	}
	ev := event.New()
	ev.Source = event.Source{Type: "sigil", Sensor: "sigil-sync", Hostname: s.cfg.Hostname}
	ev.Action = event.Action{Category: "control", Verb: "control"}
	ev.Object = event.Object{Resource: "control_cmd", Value: cmd.Cmd}
	ev.Detection = event.Detection{Method: "raw", Confidence: 1}
	ev.Severity = "info"
	if !ok {
		ev.Severity = "medium"
	}
	ev.Session = cmd.Session
	ev.PID = cmd.PID
	ev.Raw = map[string]any{
		"env_id":      envID,
		"cmd":         cmd.Cmd,
		"session":     cmd.Session,
		"pid":         cmd.PID,
		"rule_id":     cmd.RuleID,
		"mode":        cmd.Mode,
		"lock_level":  cmd.LockLevel,
		"ttl_seconds": cmd.TTLSeconds,
		"reason":      cmd.Reason,
		"peer_source": peer.Source,
		"peer_pid":    peer.PID,
		"peer_uid":    peer.UID,
		"ok":          ok,
		"outcome":     msg,
	}
	if _, err := s.cfg.Ledger.Append(ev); err != nil {
		s.cfg.Logf("sigil control_cmd ledger write failed: %v", err)
	}
}

func (s *Server) sendAck(p *peerConn, refID string, ok bool, msg string, snap *StateSnapshot) {
	env, err := NewEnvelope("sentinel-x", TypeControlAck, ControlAckPayload{
		OK: ok, RefID: refID, Message: msg, State: snap,
	})
	if err == nil {
		s.sendEnvelope(p, env)
	}
}

func (s *Server) sendEnvelope(p *peerConn, env Envelope) {
	b, err := json.Marshal(env)
	if err != nil {
		return
	}
	b = append(b, '\n')
	select {
	case p.sendCh <- b:
	default:
		s.dropped.Add(1)
	}
}

func readPeerCred(conn net.Conn) (int, int) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, -1
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, -1
	}
	var pid int
	var uid = -1
	_ = raw.Control(func(fd uintptr) {
		if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
			pid = int(cred.Pid)
			uid = int(cred.Uid)
		}
	})
	return pid, uid
}
