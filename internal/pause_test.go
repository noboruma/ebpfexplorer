package internal

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func TestNoopSpec(t *testing.T) {
	for _, c := range []struct {
		lt   link.Type
		at   ebpf.AttachType
		t    ebpf.ProgramType
		ret  int64
		fail bool
	}{
		{lt: link.XDPType, t: ebpf.XDP, ret: 2},
		{lt: link.TCXType, at: ebpf.AttachTCXIngress, t: ebpf.SchedCLS, ret: -1},
		{lt: link.NetkitType, at: ebpf.AttachNetkitPrimary, t: ebpf.SchedCLS, ret: -1},
		{lt: link.CgroupType, at: ebpf.AttachCGroupInetEgress, t: ebpf.CGroupSKB, ret: 1},
		{lt: link.CgroupType, at: ebpf.AttachCGroupInet4Connect, t: ebpf.CGroupSockAddr, ret: 1},
		{lt: link.CgroupType, at: ebpf.AttachCGroupDevice, t: ebpf.CGroupDevice, ret: 1},
		{lt: link.CgroupType, at: ebpf.AttachLSMCgroup, t: ebpf.LSM, fail: true},
		{lt: link.TracingType, t: ebpf.Tracing, fail: true},
		{lt: link.PerfEventType, t: ebpf.Kprobe, fail: true},
	} {
		spec, err := noopSpec(c.lt, c.at, c.t)
		if c.fail {
			if err == nil {
				t.Errorf("%s on %s: expected an error", c.t, linkTypeName(c.lt))
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s on %s: %v", c.t, linkTypeName(c.lt), err)
		}
		want := asm.Instructions{asm.Mov.Imm(asm.R0, int32(c.ret)), asm.Return()}
		if spec.Type != c.t || spec.AttachType != c.at || spec.Name != noopName || fmt.Sprint(spec.Instructions) != fmt.Sprint(want) {
			t.Errorf("%s on %s: got %+v", c.t, linkTypeName(c.lt), spec)
		}
	}
}

func TestPausableLinks(t *testing.T) {
	p := progRow{Attachments: []attachment{
		{label: "xdp@eth0", linkID: 1, linkType: link.XDPType},
		{label: "xdp@eth1 (native)", ifindex: 3}, // netlink, no link
		{label: "tcx@eth0", linkID: 2, linkType: link.TCXType},
		{label: "kprobe@tcp_connect", linkID: 3, linkType: link.PerfEventType},
		{label: "cgroup/device@/", cgroup: "/sys/fs/cgroup"}, // BPF_PROG_ATTACH
		{label: "cgroup/egress@/", linkID: 4, linkType: link.CgroupType},
	}}
	var got []string
	for _, a := range pausableLinks(p) {
		got = append(got, a.label)
	}
	if s := strings.Join(got, ", "); s != "xdp@eth0, tcx@eth0, cgroup/egress@/" {
		t.Fatalf("pausable: %s", s)
	}
}

func TestPauseApply(t *testing.T) {
	s := newPauseSet()
	s.links[7] = &pausedLink{id: 7, label: "xdp@eth0", origID: 41, noop: 90}
	s.links[8] = &pausedLink{id: 8, label: "tcx@eth0", origID: 41, noop: 91}
	rows := func() []progRow {
		return []progRow{
			{ID: 41, Name: "xdp_filter"},
			{ID: 90, Name: noopName, Attachments: []attachment{{label: "xdp@eth0", linkID: 7}}, Attached: "xdp@eth0"},
		}
	}

	// An incomplete list forgets nothing.
	r := rows()
	s.apply(r, false)
	if r[0].Attached != "xdp@eth0 (paused), tcx@eth0 (paused)" || len(s.links) != 2 {
		t.Fatalf("attached=%q paused=%d", r[0].Attached, len(s.links))
	}
	// Link 8 is gone from a complete list.
	r = rows()
	s.apply(r, true)
	if r[0].Attached != "xdp@eth0 (paused)" || r[1].Attached != "xdp@eth0" || len(s.links) != 1 {
		t.Fatalf("attached=%q/%q paused=%d", r[0].Attached, r[1].Attached, len(s.links))
	}
	// Both the original and its no-op find the pause.
	if len(s.pausedOf(41)) != 1 || len(s.pausedOf(90)) != 1 || len(s.pausedOf(42)) != 0 {
		t.Fatal("pausedOf")
	}
}

func TestPauseKey(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 20})
	m = next.(model)
	next, _ = m.Update(progsLoaded{rows: []progRow{
		{ID: 41, Name: "xdp_filter", Type: ebpf.XDP, Attachments: []attachment{{label: "xdp@eth0", linkID: 7, linkType: link.XDPType}}},
		{ID: 57, Name: "trace_connect", Type: ebpf.Kprobe, Attachments: []attachment{{label: "kprobe@tcp_connect", linkID: 8, linkType: link.PerfEventType}}},
	}})
	m = next.(model)

	if m = press(m, "D"); !strings.Contains(m.notice, "--allow-write") || m.pauseAsk != nil {
		t.Fatalf("read-only: notice=%q", m.notice)
	}
	if strings.Contains(m.help(), "pause") {
		t.Fatal("[D] shown while read-only")
	}

	m.allowWrite = true
	m = press(m, "D")
	if m.pauseAsk == nil || !strings.Contains(m.View(), "pause prog 41 xdp_filter on xdp@eth0?") {
		t.Fatalf("no confirmation:\n%s", m.View())
	}
	// Anything but y backs out.
	if m = press(m, "n"); m.pauseAsk != nil || len(m.pauses.links) != 0 {
		t.Fatal("pause not cancelled")
	}

	m = press(m, "j", "D")
	if !strings.Contains(m.notice, "nothing to pause") || m.pauseAsk != nil {
		t.Fatalf("kprobe: notice=%q", m.notice)
	}

	// [D] on a paused program resumes it; a link that is gone is forgotten.
	m.pauses.links[999999] = &pausedLink{id: 999999, label: "xdp@eth0", origID: 41, noop: 90}
	m = press(m, "k", "D")
	if !strings.Contains(m.notice, "resume failed") || len(m.pauses.links) != 0 {
		t.Fatalf("resume: notice=%q paused=%d", m.notice, len(m.pauses.links))
	}
}
