package internal

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
)

func TestCPUUsage(t *testing.T) {
	t0 := time.Unix(1000, 0)
	for _, c := range []struct {
		prev, cur runSample
		want      string
	}{
		{runSample{0, time.Time{}}, runSample{time.Second, t0}, "-"},                           // first sample
		{runSample{0, t0}, runSample{20 * time.Millisecond, t0.Add(2 * time.Second)}, "1.00"},  // 20ms over 2s
		{runSample{0, t0}, runSample{3 * time.Second, t0.Add(2 * time.Second)}, "150.00"},      // on several CPUs
		{runSample{0, t0}, runSample{100 * time.Nanosecond, t0.Add(2 * time.Second)}, "<0.01"}, // tiny
		{runSample{time.Second, t0}, runSample{time.Second, t0.Add(2 * time.Second)}, "0"},     // idle
		{runSample{time.Second, t0}, runSample{0, t0.Add(2 * time.Second)}, "-"},               // counter reset
		{runSample{0, t0.Add(time.Second)}, runSample{time.Second, t0}, "-"},                   // out of order
	} {
		if got := cpuText(cpuUsage(c.prev, c.cur)); got != c.want {
			t.Errorf("%v → %v: got %s, want %s", c.prev, c.cur, got, c.want)
		}
	}
}

func TestCPUColumn(t *testing.T) {
	m := initialModel(false)
	m.statsOn = true
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 20})
	m = next.(model)
	next, _ = m.Update(progsLoaded{rows: []progRow{{ID: 41, Name: "xdp_filter", Type: ebpf.XDP}}})
	m = next.(model)
	if !strings.Contains(m.View(), "CPU%") || m.cpuCell(41) != "-" {
		t.Fatalf("before samples:\n%s", m.View())
	}

	t0 := time.Unix(1000, 0)
	for _, s := range []runSample{{0, t0}, {50 * time.Millisecond, t0.Add(2 * time.Second)}} {
		next, _ = m.Update(cpuSampled{map[ebpf.ProgramID]runSample{41: s}})
		m = next.(model)
	}
	if v := m.View(); !strings.Contains(v, "2.50") {
		t.Fatalf("after samples:\n%s", v)
	}
	m = press(m, "enter")
	if v := m.View(); !strings.Contains(v, "cpu: 2.50%") {
		t.Fatalf("maps header:\n%s", v)
	}
}
