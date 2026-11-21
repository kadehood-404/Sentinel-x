//go:build linux

package tap

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

// FIMSensor performs userland File-Integrity Monitoring on sensitive paths.
//
// Design note:
//   - Watches PARENT DIRECTORIES (not individual file inodes) via Linux
//     inotify plus periodic stat snapshots. Watching parent directories catches
//     atomic temp -> rename replacements, creates, unlinks, writes/truncates,
//     and chmod/chown metadata changes even when a target file does not exist
//     yet or its inode is swapped.
//   - Explicitly scoped to MUTATION, METADATA, RENAME, CREATE, and DELETE
//     events. Userland inotify does NOT claim to detect unauthorized reads
//     (read observation requires fanotify/audit/eBPF on privileged Linux or
//     proxy/tool wrappers).
type FIMSensor struct {
	Paths        []string      // files or directories to watch
	PollInterval time.Duration // stat fallback interval; default 2s
	Hostname     string
}

func (s *FIMSensor) Name() string { return "fim" }

type watchTarget struct {
	dir       string // parent dir (or dir itself if watching a directory)
	exactName string // empty means watch all direct children of dir
}

type fileMeta struct {
	exists  bool
	size    int64
	mode    os.FileMode
	modTime int64
	ino     uint64
}

const fimInotifyMask uint32 = syscall.IN_MODIFY |
	syscall.IN_CLOSE_WRITE |
	syscall.IN_ATTRIB |
	syscall.IN_MOVED_TO |
	syscall.IN_MOVED_FROM |
	syscall.IN_CREATE |
	syscall.IN_DELETE

func (s *FIMSensor) resolveTargets() ([]watchTarget, map[string]bool) {
	var targets []watchTarget
	dirs := map[string]bool{}
	for _, raw := range s.Paths {
		p := expandHome(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		st, err := os.Stat(abs)
		if err == nil && st.IsDir() {
			targets = append(targets, watchTarget{dir: abs})
			dirs[abs] = true
			// Also watch its parent dir in case the watched directory itself is renamed/deleted.
			parent := filepath.Dir(abs)
			if parent != abs {
				targets = append(targets, watchTarget{dir: parent, exactName: filepath.Base(abs)})
				dirs[parent] = true
			}
		} else {
			parent := filepath.Dir(abs)
			targets = append(targets, watchTarget{dir: parent, exactName: filepath.Base(abs)})
			dirs[parent] = true
		}
	}
	return targets, dirs
}

func (s *FIMSensor) Run(ctx context.Context, emit func(event.Event)) error {
	targets, dirs := s.resolveTargets()
	if len(targets) == 0 {
		<-ctx.Done()
		return nil
	}
	iv := s.PollInterval
	if iv <= 0 {
		iv = 2 * time.Second
	}

	// Set up Linux inotify watches on parent directories (best-effort; falls
	// back seamlessly to stat diffing if inotify is unavailable in PRoot).
	wdToDir := map[int32]string{}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err == nil {
		defer syscall.Close(fd)
		for dir := range dirs {
			if wd, werr := syscall.InotifyAddWatch(fd, dir, fimInotifyMask); werr == nil {
				wdToDir[int32(wd)] = dir
			}
		}
	} else {
		fd = -1
	}

	// Build initial stat snapshot for fallback/dedup.
	snap := snapshotTargets(targets)

	// Fast ticker for draining non-blocking inotify fd + slower stat check.
	inoTick := time.NewTicker(50 * time.Millisecond)
	statTick := time.NewTicker(iv)
	defer inoTick.Stop()
	defer statTick.Stop()

	buf := make([]byte, 16*1024)
	recent := map[string]time.Time{}

	emitDedup := func(path, verb string) {
		key := verb + "\x00" + path
		now := time.Now()
		if last, ok := recent[key]; ok && now.Sub(last) < 250*time.Millisecond {
			return
		}
		recent[key] = now
		ev := event.New()
		ev.Source = event.Source{Type: "host", Sensor: "sentinel-tap:fim", Hostname: s.Hostname}
		ev.Action = event.Action{Category: "file", Verb: verb}
		ev.Object = event.Object{Resource: "file", Value: path}
		ev.Detection = event.Detection{Method: "raw", Confidence: 1}
		ev.Raw = map[string]any{"path": path, "verb": verb}
		emit(ev)
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-inoTick.C:
			if fd < 0 || len(wdToDir) == 0 {
				continue
			}
			for {
				n, rerr := syscall.Read(fd, buf)
				if rerr != nil {
					if errors.Is(rerr, syscall.EAGAIN) || errors.Is(rerr, syscall.EINTR) {
						break
					}
					break
				}
				if n <= 0 {
					break
				}
				parseInotifyEvents(buf[:n], wdToDir, targets, func(path, verb string) {
					emitDedup(path, verb)
					// Refresh stat snapshot for this path so the stat ticker doesn't double-fire.
					snap[path] = statPath(path)
				})
			}

		case <-statTick.C:
			cur := snapshotTargets(targets)
			for p, m := range cur {
				prev, existed := snap[p]
				if !existed && m.exists {
					emitDedup(p, "create")
				} else if existed && prev.exists && !m.exists {
					emitDedup(p, "delete")
				} else if existed && m.exists {
					switch {
					case prev.ino != 0 && m.ino != 0 && prev.ino != m.ino:
						emitDedup(p, "rename")
					case prev.mode != m.mode:
						emitDedup(p, "chmod")
					case prev.size != m.size || prev.modTime != m.modTime:
						emitDedup(p, "write")
					}
				}
			}
			for p, prev := range snap {
				if prev.exists {
					if _, ok := cur[p]; !ok {
						emitDedup(p, "delete")
					}
				}
			}
			snap = cur
		}
	}
}

func parseInotifyEvents(raw []byte, wdToDir map[int32]string, targets []watchTarget, cb func(path, verb string)) {
	offset := 0
	hdrSize := int(unsafe.Sizeof(syscall.InotifyEvent{}))
	for offset+hdrSize <= len(raw) {
		wd := int32(binary.LittleEndian.Uint32(raw[offset : offset+4]))
		mask := binary.LittleEndian.Uint32(raw[offset+4 : offset+8])
		nameLen := int(binary.LittleEndian.Uint32(raw[offset+12 : offset+16]))
		offset += hdrSize
		if offset+nameLen > len(raw) {
			break
		}
		nameBytes := raw[offset : offset+nameLen]
		offset += nameLen

		name := strings.TrimRight(string(nameBytes), "\x00")
		dir, ok := wdToDir[wd]
		if !ok || name == "" {
			continue
		}
		if !matchesAnyTarget(dir, name, targets) {
			continue
		}
		fullPath := filepath.Join(dir, name)
		verb := maskToVerb(mask)
		if verb != "" {
			cb(fullPath, verb)
		}
	}
}

func matchesAnyTarget(dir, name string, targets []watchTarget) bool {
	for _, t := range targets {
		if t.dir != dir {
			continue
		}
		if t.exactName == "" || t.exactName == name {
			return true
		}
	}
	return false
}

func maskToVerb(mask uint32) string {
	switch {
	case mask&syscall.IN_MOVED_TO != 0:
		return "rename"
	case mask&syscall.IN_ATTRIB != 0:
		return "chmod"
	case mask&syscall.IN_DELETE != 0 || mask&syscall.IN_MOVED_FROM != 0:
		return "delete"
	case mask&syscall.IN_CREATE != 0:
		return "create"
	case mask&(syscall.IN_MODIFY|syscall.IN_CLOSE_WRITE) != 0:
		return "write"
	default:
		return ""
	}
}

func snapshotTargets(targets []watchTarget) map[string]fileMeta {
	out := map[string]fileMeta{}
	for _, t := range targets {
		if t.exactName != "" {
			p := filepath.Join(t.dir, t.exactName)
			m := statPath(p)
			if m.exists {
				out[p] = m
			}
			continue
		}
		entries, err := os.ReadDir(t.dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			p := filepath.Join(t.dir, ent.Name())
			m := statPath(p)
			if m.exists {
				out[p] = m
			}
		}
	}
	return out
}

func statPath(p string) fileMeta {
	st, err := os.Lstat(p)
	if err != nil {
		return fileMeta{}
	}
	m := fileMeta{
		exists:  true,
		size:    st.Size(),
		mode:    st.Mode(),
		modTime: st.ModTime().UnixNano(),
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		m.ino = sys.Ino
	}
	return m
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return h
			}
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
