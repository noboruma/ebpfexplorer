package main

// Where programs are attached. Programs can be attached two ways:
//
//   - through a bpf_link (modern loaders, cilium/ebpf, libbpf's bpf_link
//     APIs), which the link iterator sees;
//   - "legacy" attachments that create no link: BPF_PROG_ATTACH on a cgroup
//     (systemd's sd_devices/sd_fw_* programs) and XDP set via netlink
//     (`ip link set dev X xdp ...`). These are found by querying each cgroup
//     and reading each interface's IFLA_XDP attributes.
//
// Kprobes, uprobes and tracepoints attached without a link are found in
// probes.go. Not covered: classic tc (cls_bpf) filters, socket filters and
// sockmap verdicts, which are attached to objects that can't be enumerated
// cheaply.

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// attachments maps program IDs to where they are attached, for all sources.
// attachment is one place a program is attached. The extra fields identify
// it so the same attachment seen by several sources is shown once.
type attachment struct {
	label string

	linkID link.ID // non-zero: attached through a bpf_link

	cgroup string // cgroup directory, for cgroup hooks
	attach ebpf.AttachType

	ifindex int    // interface, for XDP
	xdpMode string // native, generic or offload
}

// attachments maps program IDs to where they are attached, for all sources.
func attachments(progTypes map[ebpf.ProgramType]bool) map[ebpf.ProgramID][]attachment {
	out := linkAttachments()

	for id, cgs := range cgroupAttachments(progTypes) {
		// A cgroup bpf_link also shows up in the query: list it once, with
		// the query's more precise label.
		for _, cg := range cgs {
			if i := slices.IndexFunc(out[id], func(a attachment) bool { return a.linkID != 0 && a.label == "cgroup" }); i >= 0 {
				out[id][i].label, out[id][i].cgroup, out[id][i].attach = cg.label, cg.cgroup, cg.attach
				continue
			}
			out[id] = append(out[id], cg)
		}
	}
	for id, ps := range perfEventFdAttachments(progTypes) {
		// A loader may keep the perf event fd behind a perf_event link:
		// both report the same label, list it once.
		for _, p := range ps {
			if !hasLabel(out[id], p.label) {
				out[id] = append(out[id], p)
			}
		}
	}
	for id, xs := range xdpNetlinkAttachments() {
		for _, x := range xs {
			// Netlink also reports XDP attached through a link; merge them so
			// it is listed once, with the mode in the label.
			if i := slices.IndexFunc(out[id], func(a attachment) bool { return a.linkID != 0 && a.ifindex == x.ifindex }); i >= 0 {
				out[id][i].label, out[id][i].xdpMode = x.label, x.xdpMode
				continue
			}
			out[id] = append(out[id], x)
		}
	}
	return out
}

func attachmentLabels(as []attachment) string {
	labels := make([]string, 0, len(as))
	for _, a := range as {
		if !slices.Contains(labels, a.label) {
			labels = append(labels, a.label)
		}
	}
	return strings.Join(labels, ", ")
}

// linkAttachments describes the bpf_links each program is attached through.
func linkAttachments() map[ebpf.ProgramID][]attachment {
	out := map[ebpf.ProgramID][]attachment{}
	it := new(link.Iterator)
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			continue
		}
		a := attachment{label: linkTypeName(info.Type), linkID: info.ID}
		switch {
		case info.XDP() != nil:
			a.ifindex = int(info.XDP().Ifindex)
			a.label = "xdp@" + ifName(info.XDP().Ifindex)
		case info.TCX() != nil:
			a.label = "tcx@" + ifName(info.TCX().Ifindex)
		case info.Netkit() != nil:
			a.label = "netkit@" + ifName(info.Netkit().Ifindex)
		case info.PerfEvent() != nil:
			a.label = perfLinkLabel(info.PerfEvent())
		case info.RawTracepoint() != nil:
			a.label = "raw_tp@" + info.RawTracepoint().Name
		case info.KprobeMulti() != nil:
			a.label = fmt.Sprintf("kprobe_multi (%d functions)", info.KprobeMulti().Count)
		}
		out[info.Program] = append(out[info.Program], a)
	}
	return out
}

// cgroupHooks lists, per cgroup program type, the attach points to query
// and the short name shown for each.
var cgroupHooks = map[ebpf.ProgramType][]struct {
	attach ebpf.AttachType
	name   string
}{
	ebpf.CGroupDevice: {{ebpf.AttachCGroupDevice, "device"}},
	ebpf.CGroupSKB:    {{ebpf.AttachCGroupInetIngress, "ingress"}, {ebpf.AttachCGroupInetEgress, "egress"}},
	ebpf.CGroupSock: {
		{ebpf.AttachCGroupInetSockCreate, "sock_create"}, {ebpf.AttachCgroupInetSockRelease, "sock_release"},
		{ebpf.AttachCGroupInet4PostBind, "post_bind4"}, {ebpf.AttachCGroupInet6PostBind, "post_bind6"},
	},
	ebpf.CGroupSockAddr: {
		{ebpf.AttachCGroupInet4Bind, "bind4"}, {ebpf.AttachCGroupInet6Bind, "bind6"},
		{ebpf.AttachCGroupInet4Connect, "connect4"}, {ebpf.AttachCGroupInet6Connect, "connect6"},
		{ebpf.AttachCGroupUDP4Sendmsg, "sendmsg4"}, {ebpf.AttachCGroupUDP6Sendmsg, "sendmsg6"},
		{ebpf.AttachCGroupUDP4Recvmsg, "recvmsg4"}, {ebpf.AttachCGroupUDP6Recvmsg, "recvmsg6"},
		{ebpf.AttachCgroupInet4GetPeername, "getpeername4"}, {ebpf.AttachCgroupInet6GetPeername, "getpeername6"},
		{ebpf.AttachCgroupInet4GetSockname, "getsockname4"}, {ebpf.AttachCgroupInet6GetSockname, "getsockname6"},
		{ebpf.AttachCgroupUnixConnect, "unix_connect"}, {ebpf.AttachCgroupUnixSendmsg, "unix_sendmsg"},
		{ebpf.AttachCgroupUnixRecvmsg, "unix_recvmsg"},
	},
	ebpf.SockOps:       {{ebpf.AttachCGroupSockOps, "sock_ops"}},
	ebpf.CGroupSysctl:  {{ebpf.AttachCGroupSysctl, "sysctl"}},
	ebpf.CGroupSockopt: {{ebpf.AttachCGroupGetsockopt, "getsockopt"}, {ebpf.AttachCGroupSetsockopt, "setsockopt"}},
}

// cgroupAttachments queries every cgroup v2 directory for directly attached
// programs. Only the hooks of program types actually loaded are queried, so
// a machine without cgroup programs pays nothing.
func cgroupAttachments(progTypes map[ebpf.ProgramType]bool) map[ebpf.ProgramID][]attachment {
	out := map[ebpf.ProgramID][]attachment{}
	type hook struct {
		attach ebpf.AttachType
		name   string
	}
	var hooks []hook
	for t, hs := range cgroupHooks {
		if progTypes[t] {
			for _, h := range hs {
				hooks = append(hooks, hook{h.attach, h.name})
			}
		}
	}
	if len(hooks) == 0 {
		return out
	}
	root := cgroup2Root()
	if root == "" {
		return out
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil
		}
		defer unix.Close(fd)
		// The last path element (e.g. "systemd-udevd.service") identifies a
		// cgroup well enough and keeps the column readable; "/" is the root.
		rel := filepath.Base(path)
		if path == root {
			rel = "/"
		}
		for _, h := range hooks {
			res, err := link.QueryPrograms(link.QueryOptions{Target: fd, Attach: h.attach})
			if err != nil {
				continue
			}
			for _, p := range res.Programs {
				out[p.ID] = append(out[p.ID], attachment{
					label:  fmt.Sprintf("cgroup/%s@%s", h.name, rel),
					cgroup: path,
					attach: h.attach,
				})
			}
		}
		return nil
	})
	return out
}

// cgroup2Root finds the cgroup v2 hierarchy: /sys/fs/cgroup on unified
// systems, /sys/fs/cgroup/unified on hybrid (v1+v2) ones.
func cgroup2Root() string {
	for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
			return p
		}
	}
	return ""
}

// XDP attach modes reported in IFLA_XDP_ATTACHED (uapi/linux/if_link.h).
const (
	xdpAttachedNone = iota
	xdpAttachedDrv
	xdpAttachedSKB
	xdpAttachedHW
	xdpAttachedMulti
)

// xdpNetlinkAttachments reads each interface's XDP programs from an
// RTM_GETLINK dump, which covers XDP attached with or without a bpf_link.
func xdpNetlinkAttachments() map[ebpf.ProgramID][]attachment {
	out := map[ebpf.ProgramID][]attachment{}
	data, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return out
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return out
	}
	for i := range msgs {
		if msgs[i].Header.Type != unix.RTM_NEWLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msgs[i])
		if err != nil || len(msgs[i].Data) < unix.SizeofIfInfomsg {
			continue
		}
		ifindex := int(int32(binary.NativeEndian.Uint32(msgs[i].Data[4:8]))) // ifinfomsg.ifi_index
		var name string
		var xdp []byte
		for _, a := range attrs {
			switch a.Attr.Type &^ unix.NLA_F_NESTED {
			case unix.IFLA_IFNAME:
				name = strings.TrimRight(string(a.Value), "\x00")
			case unix.IFLA_XDP:
				xdp = a.Value
			}
		}
		for id, mode := range parseIFLAXDP(xdp) {
			out[id] = append(out[id], attachment{
				label:   fmt.Sprintf("xdp@%s (%s)", name, mode),
				ifindex: ifindex,
				xdpMode: mode,
			})
		}
	}
	return out
}

// parseIFLAXDP decodes the nested IFLA_XDP attribute into program → mode.
func parseIFLAXDP(b []byte) map[ebpf.ProgramID]string {
	out := map[ebpf.ProgramID]string{}
	var attached uint8
	ids := map[uint16]uint32{}
	for len(b) >= unix.SizeofRtAttr {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		typ := binary.NativeEndian.Uint16(b[2:4]) &^ unix.NLA_F_NESTED
		if l < unix.SizeofRtAttr || l > len(b) {
			break
		}
		val := b[unix.SizeofRtAttr:l]
		switch {
		case typ == unix.IFLA_XDP_ATTACHED && len(val) >= 1:
			attached = val[0]
		case len(val) >= 4:
			ids[typ] = binary.NativeEndian.Uint32(val)
		}
		b = b[min(len(b), (l+unix.RTA_ALIGNTO-1)&^(unix.RTA_ALIGNTO-1)):]
	}

	add := func(attr uint16, mode string) {
		if id := ids[attr]; id != 0 {
			out[ebpf.ProgramID(id)] = mode
		}
	}
	switch attached {
	case xdpAttachedDrv:
		add(unix.IFLA_XDP_PROG_ID, "native")
	case xdpAttachedSKB:
		add(unix.IFLA_XDP_PROG_ID, "generic")
	case xdpAttachedHW:
		add(unix.IFLA_XDP_PROG_ID, "offload")
	case xdpAttachedMulti:
		add(unix.IFLA_XDP_DRV_PROG_ID, "native")
		add(unix.IFLA_XDP_SKB_PROG_ID, "generic")
		add(unix.IFLA_XDP_HW_PROG_ID, "offload")
	}
	return out
}
