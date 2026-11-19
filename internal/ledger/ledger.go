// Package ledger is an append-only, hash-chained audit log (JSON Lines).
//
// Each record commits to the previous record's hash, so editing or removing
// a record in the middle of the file is detectable with Verify. It does NOT
// detect truncation of the tail on its own: anchor the latest hash somewhere
// else (a remote host, a printout) if that matters to you.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Genesis is the "previous hash" of the first record.
var Genesis = strings.Repeat("0", 64)

type Record struct {
	Seq  uint64          `json:"seq"`
	TS   string          `json:"ts"`
	Prev string          `json:"prev"`
	Hash string          `json:"hash"`
	Data json.RawMessage `json:"data"`
}

type Ledger struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	prev string
}

// Open opens (creating if needed) the ledger at path and resumes its chain.
func Open(path string) (*Ledger, error) {
	n, last, err := scan(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ledger %s is not intact, refusing to append: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Ledger{f: f, seq: n, prev: Genesis}
	if n > 0 {
		l.prev = last
	}
	return l, nil
}

// Append writes v as the next record in the chain and syncs it to disk.
func (l *Ledger) Append(v any) (Record, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return Record{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	rec := Record{
		Seq:  l.seq + 1,
		TS:   time.Now().UTC().Format(time.RFC3339Nano),
		Prev: l.prev,
		Data: data,
	}
	rec.Hash = digest(rec.Prev, rec.Seq, rec.TS, rec.Data)

	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Record{}, err
	}
	l.seq, l.prev = rec.Seq, rec.Hash
	return rec, nil
}

// Head returns the sequence number and hash of the latest record.
func (l *Ledger) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.prev
}

func (l *Ledger) Close() error { return l.f.Close() }

// Verify checks the whole chain and returns the number of records.
func Verify(path string) (uint64, error) {
	n, _, err := scan(path)
	return n, err
}

func scan(path string) (uint64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)

	prev := Genesis
	var n uint64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return n, prev, fmt.Errorf("record %d: unreadable: %w", n+1, err)
		}
		if r.Seq != n+1 {
			return n, prev, fmt.Errorf("record %d: sequence is %d (record removed or reordered)", n+1, r.Seq)
		}
		if r.Prev != prev {
			return n, prev, fmt.Errorf("record %d: chain broken (prev hash mismatch)", r.Seq)
		}
		if want := digest(r.Prev, r.Seq, r.TS, r.Data); r.Hash != want {
			return n, prev, fmt.Errorf("record %d: contents modified (hash mismatch)", r.Seq)
		}
		prev = r.Hash
		n++
	}
	if err := sc.Err(); err != nil {
		return n, prev, err
	}
	return n, prev, nil
}

func digest(prev string, seq uint64, ts string, data []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%d\n%s\n", prev, seq, ts)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
