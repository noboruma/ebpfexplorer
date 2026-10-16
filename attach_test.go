package main

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func rtattr(typ uint16, val []byte) []byte {
	b := binary.NativeEndian.AppendUint16(nil, uint16(unix.SizeofRtAttr+len(val)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, val...)
	for len(b)%unix.RTA_ALIGNTO != 0 {
		b = append(b, 0)
	}
	return b
}

func TestContainsLine(t *testing.T) {
	info := "pos:\t0\nflags:\t02000002\nprog_type:\t6\nprog_id:\t41\n"
	if !containsLine(info, "prog_id:\t41") || containsLine(info, "prog_id:\t4") {
		t.Fatal("containsLine must match whole lines only")
	}
}

func TestParseIFLAXDP(t *testing.T) {
	u32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

	single := cat(rtattr(unix.IFLA_XDP_ATTACHED, []byte{xdpAttachedSKB}), rtattr(unix.IFLA_XDP_PROG_ID, u32(77)))
	if got := parseIFLAXDP(single); len(got) != 1 || got[77] != "generic" {
		t.Fatalf("single: %v", got)
	}

	multi := cat(
		rtattr(unix.IFLA_XDP_ATTACHED, []byte{xdpAttachedMulti}),
		rtattr(unix.IFLA_XDP_DRV_PROG_ID, u32(10)),
		rtattr(unix.IFLA_XDP_SKB_PROG_ID, u32(11)),
	)
	got := parseIFLAXDP(multi)
	if got[10] != "native" || got[11] != "generic" || len(got) != 2 {
		t.Fatalf("multi: %v", got)
	}

	if got := parseIFLAXDP(rtattr(unix.IFLA_XDP_ATTACHED, []byte{xdpAttachedNone})); len(got) != 0 {
		t.Fatalf("none: %v", got)
	}
	if got := parseIFLAXDP([]byte{0xff, 0xff, 1}); len(got) != 0 { // truncated input
		t.Fatalf("garbage: %v", got)
	}
}

// The netlink dump and cgroup walk need no privileges to run (queries just
// return nothing without CAP_BPF); make sure they don't fail or panic.
func TestAttachmentSourcesRun(t *testing.T) {
	t.Logf("cgroup2 root: %q", cgroup2Root())
	t.Logf("xdp via netlink: %v", xdpNetlinkAttachments())
	t.Logf("cgroup: %d programs", len(cgroupAttachments(map[ebpf.ProgramType]bool{ebpf.CGroupDevice: true})))
}
