package internal

// CPU used by programs. The kernel only counts each program's run time while
// BPF statistics are enabled: either system-wide (sysctl
// kernel.bpf_stats_enabled=1) or for as long as some process holds a
// BPF_ENABLE_STATS fd, which the explorer does while it runs. Counting adds a
// clock read to every program run.
//
// The run time is sampled every cpuInterval; a program's CPU% is the run
// time it gained over the wall time between two samples, as in top: 100% is
// one CPU fully busy, a program running on several CPUs can go above.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const cpuInterval = 2 * time.Second

// enableStats starts the kernel's run time accounting. The closer stops it,
// unless the sysctl has it on anyway; it is nil when the sysctl alone does.
func enableStats() (io.Closer, error) {
	c, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err == nil {
		return c, nil
	}
	if b, rerr := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled"); rerr == nil && strings.TrimSpace(string(b)) == "1" {
		return nil, nil
	}
	return nil, err
}

type runSample struct {
	runtime time.Duration
	at      time.Time
}

type cpuTick struct{}

type cpuSampled struct {
	samples map[ebpf.ProgramID]runSample
}

func cpuTickCmd() tea.Cmd {
	return tea.Tick(cpuInterval, func(time.Time) tea.Msg { return cpuTick{} })
}

func sampleCPUCmd(ids []ebpf.ProgramID) tea.Cmd {
	return func() tea.Msg { return cpuSampled{sampleRuntimes(ids)} }
}

// sampleRuntimes reads the total run time of each program still loaded.
func sampleRuntimes(ids []ebpf.ProgramID) map[ebpf.ProgramID]runSample {
	out := make(map[ebpf.ProgramID]runSample, len(ids))
	for _, id := range ids {
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		st, err := p.Stats()
		p.Close()
		if err == nil {
			out[id] = runSample{st.Runtime, time.Now()}
		}
	}
	return out
}

// cpuUsage turns two samples into a CPU percentage, if they can be compared.
func cpuUsage(prev, cur runSample) (float64, bool) {
	wall := cur.at.Sub(prev.at)
	if prev.at.IsZero() || wall <= 0 || cur.runtime < prev.runtime {
		return 0, false
	}
	return float64(cur.runtime-prev.runtime) / float64(wall) * 100, true
}

func cpuText(pct float64, ok bool) string {
	switch {
	case !ok:
		return "-"
	case pct == 0:
		return "0"
	case pct < 0.01:
		return "<0.01"
	}
	return fmt.Sprintf("%.2f", pct)
}

// onCPUSampled updates each program's CPU% from the previous sample.
func (m *model) onCPUSampled(msg cpuSampled) {
	cpu := make(map[ebpf.ProgramID]float64, len(msg.samples))
	for id, cur := range msg.samples {
		if pct, ok := cpuUsage(m.cpuPrev[id], cur); ok {
			cpu[id] = pct
		}
	}
	m.cpu, m.cpuPrev = cpu, msg.samples
}

// cpuCell is the CPU% shown for a program: "-" until two samples are in, or
// without statistics.
func (m model) cpuCell(id ebpf.ProgramID) string {
	pct, ok := m.cpu[id]
	return cpuText(pct, ok)
}

// sampling reports whether the screen shows CPU usage.
func (m model) sampling() bool {
	return m.statsOn && (m.view == viewProgs || m.view == viewMaps && !m.allMaps)
}

func (m model) progIDs() []ebpf.ProgramID {
	ids := make([]ebpf.ProgramID, len(m.progs))
	for i, p := range m.progs {
		ids[i] = p.ID
	}
	return ids
}
