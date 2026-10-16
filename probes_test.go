package main

import (
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestProbeLabel(t *testing.T) {
	for _, tc := range []struct {
		kind, target string
		off, addr    uint64
		want         string
	}{
		{"kprobe", "tcp_connect", 0, 0, "kprobe@tcp_connect"},
		{"kretprobe", "tcp_connect", 0x10, 0, "kretprobe@tcp_connect+0x10"},
		{"uprobe", "/usr/bin/curl", 0x1f0, 0, "uprobe@/usr/bin/curl+0x1f0"},
		{"kprobe", "", 0, 0xffffffff81000000, "kprobe@0xffffffff81000000"},
		{"kprobe", "", 0, 0, "kprobe@?"},
	} {
		if got := probeLabel(tc.kind, tc.target, tc.off, tc.addr); got != tc.want {
			t.Errorf("probeLabel(%q, %q, %#x, %#x) = %q, want %q", tc.kind, tc.target, tc.off, tc.addr, got, tc.want)
		}
	}
}

func TestPerfLinkLabelWithoutDetails(t *testing.T) {
	// Older kernels report the perf event type but no details. Type has an
	// internal type in cilium, so set it through reflection.
	for typ, want := range map[uint64]string{3: "kprobe", 4: "kretprobe", 1: "uprobe", 2: "uretprobe", 5: "tracepoint", 6: "perf_event"} {
		var pe link.PerfEventInfo
		reflect.ValueOf(&pe).Elem().FieldByName("Type").SetUint(typ)
		if got := perfLinkLabel(&pe); got != want {
			t.Errorf("type %d: %q, want %q", typ, got, want)
		}
	}
}

// BPF_TASK_FD_QUERY on a non perf-event fd must fail cleanly (EPERM without
// privileges, ENOTSUPP/EBADF otherwise), and the /proc scan must not panic.
func TestTaskFdQueryRuns(t *testing.T) {
	f, err := os.Open("/proc/self/stat")
	if err != nil {
		t.Skip(err)
	}
	defer f.Close()
	if q, err := taskFdQuery(os.Getpid(), int(f.Fd())); err == nil && q.progID != 0 {
		t.Fatalf("a regular file reported BPF program %d", q.progID)
	}
	t.Logf("probes found: %v", perfEventFdAttachments(map[ebpf.ProgramType]bool{ebpf.Kprobe: true}))
}
