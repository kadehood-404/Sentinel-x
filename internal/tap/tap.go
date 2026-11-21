// Package tap implements sentinel-tap: lightweight host telemetry sensors
// (process exec/priv-esc, parent-directory file-integrity monitoring, and
// outbound socket tracking).
//
// The userland Linux backend (/proc + inotify/stat) is first-class and runs
// with zero elevated privileges (including PRoot, containers, and WSL). An
// optional capability-gated eBPF interface is provided for privileged Linux
// hosts.
package tap

import (
	"context"
	"sync"

	"github.com/kadehood-404/sentinel-x/internal/event"
)

// Sensor emits canonical Sentinel-X telemetry events until ctx is canceled.
type Sensor interface {
	Name() string
	Run(ctx context.Context, emit func(event.Event)) error
}

// Manager runs multiple sensors concurrently and forwards events to emit.
type Manager struct {
	Sensors []Sensor
	Logf    func(string, ...any)
}

// Run starts all configured sensors and blocks until ctx is canceled.
func (m *Manager) Run(ctx context.Context, emit func(event.Event)) {
	logf := m.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	var wg sync.WaitGroup
	for _, s := range m.Sensors {
		if s == nil {
			continue
		}
		wg.Add(1)
		go func(sensor Sensor) {
			defer wg.Done()
			if err := sensor.Run(ctx, emit); err != nil && ctx.Err() == nil {
				logf("sensor %s stopped: %v", sensor.Name(), err)
			}
		}(s)
	}
	wg.Wait()
}
