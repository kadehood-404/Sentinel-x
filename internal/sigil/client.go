package sigil

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Client talks to Sentinel-X over sigil.sock using SiGiL IPC v1 NDJSON.
type Client struct {
	sockPath string
	source   string
	conn     net.Conn
	sc       *bufio.Scanner
	wmu      sync.Mutex
}

// Dial connects to sockPath as source.
func Dial(sockPath, source string) (*Client, error) {
	if sockPath == "" {
		sockPath = DefaultSocketPath()
	}
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 8192), MaxFrameBytes)
	return &Client{sockPath: sockPath, source: source, conn: conn, sc: sc}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// Send writes a single NDJSON envelope to sigil.sock.
func (c *Client) Send(env Envelope) error {
	if env.V == 0 {
		env.V = ProtocolVersion
	}
	if env.Source == "" {
		env.Source = c.source
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err = c.conn.Write(append(b, '\n'))
	return err
}

// SendRaw writes a raw JSON line (useful for testing legacy sigil-proxy payloads).
func (c *Client) SendRaw(raw []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_, err := c.conn.Write(append(raw, '\n'))
	return err
}

// ReadNext reads the next envelope from the socket.
func (c *Client) ReadNext(timeout time.Duration) (Envelope, error) {
	if timeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	} else {
		_ = c.conn.SetReadDeadline(time.Time{})
	}
	if !c.sc.Scan() {
		if err := c.sc.Err(); err != nil {
			return Envelope{}, err
		}
		return Envelope{}, fmt.Errorf("sigil socket closed")
	}
	return DecodeFrame(c.sc.Bytes())
}

// Hello identifies the client, subscribes to message types, and optionally
// requests an immediate state_snapshot.
func (c *Client) Hello(subs []string, wantSnapshot bool) error {
	env, err := NewEnvelope(c.source, TypeHello, HelloPayload{
		Subscriptions: subs, WantSnapshot: wantSnapshot,
	})
	if err != nil {
		return err
	}
	return c.Send(env)
}

// RequestControl sends a control_cmd and waits for the matching control_ack.
func (c *Client) RequestControl(cmd ControlCmdPayload) (ControlAckPayload, error) {
	env, err := NewEnvelope(c.source, TypeControlCmd, cmd)
	if err != nil {
		return ControlAckPayload{}, err
	}
	if err := c.Send(env); err != nil {
		return ControlAckPayload{}, err
	}
	for {
		resp, err := c.ReadNext(5 * time.Second)
		if err != nil {
			return ControlAckPayload{}, err
		}
		if resp.Type != TypeControlAck {
			continue
		}
		var ack ControlAckPayload
		if err := json.Unmarshal(resp.Payload, &ack); err != nil {
			return ControlAckPayload{}, err
		}
		if ack.RefID == "" || ack.RefID == env.ID {
			return ack, nil
		}
	}
}

// SendThreatSignal sends a threat_signal and waits for acknowledgement.
func (c *Client) SendThreatSignal(sig ThreatSignalPayload) (ControlAckPayload, error) {
	env, err := NewEnvelope(c.source, TypeThreatSignal, sig)
	if err != nil {
		return ControlAckPayload{}, err
	}
	if err := c.Send(env); err != nil {
		return ControlAckPayload{}, err
	}
	resp, err := c.ReadNext(5 * time.Second)
	if err != nil {
		return ControlAckPayload{}, err
	}
	var ack ControlAckPayload
	_ = json.Unmarshal(resp.Payload, &ack)
	return ack, nil
}

// Stream reads incoming envelopes until ctx is canceled or the connection closes.
func (c *Client) Stream(ctx context.Context, out chan<- Envelope) error {
	go func() {
		<-ctx.Done()
		_ = c.conn.SetReadDeadline(time.Now())
	}()
	for {
		env, err := c.ReadNext(0)
		if err != nil {
			return err
		}
		select {
		case out <- env:
		case <-ctx.Done():
			return nil
		}
	}
}
