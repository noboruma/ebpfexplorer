package main

// Where kprobes, uprobes and tracepoints are attached.
//
// Modern loaders attach them through a perf_event bpf_link, which the link
// iterator reports with the probed function / file / tracepoint. Older ones
// (bcc, older libbpf, plain perf_event_open + PERF_EVENT_IOC_SET_BPF) create
// no link: the attachment only exists as a perf event fd in the loader's
// process. Those are found like `bpftool perf` does: scan /proc/*/fd for
// perf event fds and ask the kernel with BPF_TASK_FD_QUERY.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// probeLabel formats a probe the same way for both sources so that one seen
// through a link and through its perf event fd is listed once.
func probeLabel(kind, target string, offset, addr uint64) string {
	switch {
	case target == "" && addr != 0:
		target = fmt.Sprintf("0x%x", addr)
	case target == "":
		target = "?"
	}
	if offset != 0 {
		target += fmt.Sprintf("+0x%x", offset)
	}
	return kind + "@" + target
}

// sys.PerfEventType values (BPF_PERF_EVENT_*), an internal type in cilium.
const (
	perfEventUprobe     = 1
	perfEventURetprobe  = 2
	perfEventKprobe     = 3
	perfEventKRetprobe  = 4
	perfEventTracepoint = 5
)

// perfLinkLabel describes a perf_event bpf_link.
func perfLinkLabel(pe *link.PerfEventInfo) string {
	switch uint32(pe.Type) {
	case perfEventKprobe, perfEventKRetprobe:
		kind := "kprobe"
		if uint32(pe.Type) == perfEventKRetprobe {
			kind = "kretprobe"
		}
		if k := pe.Kprobe(); k != nil {
			return probeLabel(kind, k.Function, uint64(k.Offset), k.Address)
		}
		return kind
	case perfEventUprobe, perfEventURetprobe:
		kind := "uprobe"
		if uint32(pe.Type) == perfEventURetprobe {
			kind = "uretprobe"
		}
		if u := pe.Uprobe(); u != nil {
			return probeLabel(kind, u.File, uint64(u.Offset), 0)
		}
		return kind
	case perfEventTracepoint:
		if t := pe.Tracepoint(); t != nil {
			return "tracepoint@" + t.Tracepoint
		}
		return "tracepoint"
	}
	return "perf_event"
}

// tracingProgTypes are the program types that can be attached to perf
// events; the /proc scan only runs when one of them is loaded.
var tracingProgTypes = []ebpf.ProgramType{ebpf.Kprobe, ebpf.TracePoint, ebpf.RawTracepoint, ebpf.PerfEvent}

// bpf_task_fd_type, uapi/linux/bpf.h.
var taskFdTypes = map[uint32]string{
	0: "raw_tp",
	1: "tracepoint",
	2: "kprobe",
	3: "kretprobe",
	4: "uprobe",
	5: "uretprobe",
}

// perfEventFdAttachments finds probes attached without a bpf_link by
// querying every perf event fd of every process.
func perfEventFdAttachments(progTypes map[ebpf.ProgramType]bool) map[ebpf.ProgramID][]attachment {
	out := map[ebpf.ProgramID][]attachment{}
	needed := false
	for _, t := range tracingProgTypes {
		needed = needed || progTypes[t]
	}
	if !needed {
		return out
	}
	self := os.Getpid()
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == self {
			continue
		}
		dir := "/proc/" + p.Name() + "/fd/"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range fds {
			if target, err := os.Readlink(dir + f.Name()); err != nil || target != "anon_inode:[perf_event]" {
				continue
			}
			fd, err := strconv.Atoi(f.Name())
			if err != nil {
				continue
			}
			q, err := taskFdQuery(pid, fd)
			if err != nil || q.progID == 0 {
				continue // a perf event without a BPF program
			}
			kind, ok := taskFdTypes[q.fdType]
			if !ok {
				continue
			}
			label := probeLabel(kind, q.name, q.offset, q.addr)
			if kind == "tracepoint" || kind == "raw_tp" {
				label = kind + "@" + q.name
			}
			id := ebpf.ProgramID(q.progID)
			if !hasLabel(out[id], label) {
				out[id] = append(out[id], attachment{label: label})
			}
		}
	}
	return out
}

func hasLabel(as []attachment, label string) bool {
	for _, a := range as {
		if a.label == label {
			return true
		}
	}
	return false
}

type taskFdInfo struct {
	progID, fdType uint32
	name           string
	offset, addr   uint64
}

const bpfTaskFdQuery = 20 // BPF_TASK_FD_QUERY

// taskFdQuery runs BPF_TASK_FD_QUERY on another process's fd. The attr is
// the task_fd_query member of union bpf_attr:
//
//	u32 pid, fd, flags, buf_len; u64 buf; u32 prog_id, fd_type; u64 probe_offset, probe_addr
func taskFdQuery(pid, fd int) (taskFdInfo, error) {
	var attr [48]byte
	buf := make([]byte, 4096)
	binary.NativeEndian.PutUint32(attr[0:], uint32(pid))
	binary.NativeEndian.PutUint32(attr[4:], uint32(fd))
	binary.NativeEndian.PutUint32(attr[12:], uint32(len(buf)))
	binary.NativeEndian.PutUint64(attr[16:], uint64(uintptr(unsafe.Pointer(&buf[0]))))
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfTaskFdQuery, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if errno != 0 {
		return taskFdInfo{}, errno
	}
	n := min(int(binary.NativeEndian.Uint32(attr[12:])), len(buf)) // kernel writes back the name length
	return taskFdInfo{
		progID: binary.NativeEndian.Uint32(attr[24:]),
		fdType: binary.NativeEndian.Uint32(attr[28:]),
		name:   strings.TrimRight(string(buf[:n]), "\x00"),
		offset: binary.NativeEndian.Uint64(attr[32:]),
		addr:   binary.NativeEndian.Uint64(attr[40:]),
	}, nil
}
