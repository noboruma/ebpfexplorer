package internal

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type progRow struct {
	ID          ebpf.ProgramID
	Name        string
	Type        ebpf.ProgramType
	Tag         string
	MapIDs      []ebpf.MapID
	Attached    string // human readable summary of Attachments
	Attachments []attachment
}

type mapRow struct {
	ID         ebpf.MapID
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Err        error

	Count    int // -1 while counting
	CountErr error
}

// listPrograms walks every BPF program ID loaded in the kernel.
func listPrograms() ([]progRow, error) {
	var rows []progRow
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return rows, fmt.Errorf("get next program id: %w", err)
		}
		id = next

		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			// Program may have been unloaded between the two calls.
			continue
		}
		info, err := p.Info()
		p.Close()
		if err != nil {
			continue
		}
		mapIDs, _ := info.MapIDs()
		rows = append(rows, progRow{
			ID:     id,
			Name:   info.Name,
			Type:   info.Type,
			Tag:    info.Tag,
			MapIDs: mapIDs,
		})
	}

	types := map[ebpf.ProgramType]bool{}
	for _, r := range rows {
		types[r.Type] = true
	}
	attach := attachments(types)
	for i := range rows {
		rows[i].Attachments = attach[rows[i].ID]
		rows[i].Attached = attachmentLabels(rows[i].Attachments)
	}
	return rows, nil
}

func linkTypeName(t link.Type) string {
	switch t {
	case link.RawTracepointType:
		return "raw_tp"
	case link.TracingType:
		return "tracing"
	case link.CgroupType:
		return "cgroup"
	case link.IterType:
		return "iter"
	case link.NetNsType:
		return "netns"
	case link.XDPType:
		return "xdp"
	case link.PerfEventType:
		return "perf_event"
	case link.KprobeMultiType:
		return "kprobe_multi"
	case link.TCXType:
		return "tcx"
	case link.UprobeMultiType:
		return "uprobe_multi"
	case link.NetfilterType:
		return "netfilter"
	case link.NetkitType:
		return "netkit"
	case link.StructOpsType:
		return "struct_ops"
	}
	return fmt.Sprintf("link_type_%d", t)
}

func ifName(idx uint32) string {
	if iface, err := net.InterfaceByIndex(int(idx)); err == nil {
		return iface.Name
	}
	return fmt.Sprintf("if%d", idx)
}

func loadMaps(ids []ebpf.MapID) []mapRow {
	rows := make([]mapRow, 0, len(ids))
	for _, id := range ids {
		row := mapRow{ID: id, Count: -1}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			row.Err = err
			rows = append(rows, row)
			continue
		}
		info, err := m.Info()
		m.Close()
		if err != nil {
			row.Err = err
		} else {
			row.Name = info.Name
			row.Type = info.Type
			row.KeySize = info.KeySize
			row.ValueSize = info.ValueSize
			row.MaxEntries = info.MaxEntries
			row.Flags = info.Flags
		}
		rows = append(rows, row)
	}
	return rows
}

// listAllMaps returns every map loaded in the kernel, used or not by a
// listed program (link targets can be any map).
func listAllMaps() ([]mapRow, error) {
	var ids []ebpf.MapID
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("get next map id: %w", err)
		}
		id = next
		ids = append(ids, id)
	}
	rows := loadMaps(ids)
	// Maps unloaded between the two calls.
	return slices.DeleteFunc(rows, func(r mapRow) bool { return r.Err != nil }), nil
}

// countEntries returns how many keys a map holds. Array maps always hold
// max_entries elements; other maps are walked key by key, which needs no value
// copies but is still O(n) syscalls.
func countEntries(id ebpf.MapID) (int, error) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return 0, err
	}
	defer m.Close()

	switch m.Type() {
	case ebpf.Array, ebpf.PerCPUArray:
		return int(m.MaxEntries()), nil
	case ebpf.PerfEventArray, ebpf.RingBuf, ebpf.UserRingbuf:
		return 0, errNotIterable
	}

	n := 0
	var key any // nil starts from the first key
	for {
		next, err := m.NextKeyBytes(key)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if next == nil {
			return n, nil
		}
		n++
		key = next
	}
}

var errNotIterable = errors.New("not iterable")

func isPerCPU(t ebpf.MapType) bool {
	switch t {
	case ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUCPUHash, ebpf.PerCPUCGroupStorage:
		return true
	}
	return false
}

// --- formatting helpers ---

func hexBytes(b []byte, max int) string {
	if len(b) == 0 {
		return "-"
	}
	s := b
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	parts := make([]string, len(s))
	for i, c := range s {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	out := strings.Join(parts, " ")
	if len(s) < len(b) {
		out += " …"
	}
	return out
}

// decode gives a best-effort interpretation of small fixed-size values.
func decode(b []byte) string {
	switch len(b) {
	case 1:
		return fmt.Sprintf("%d", b[0])
	case 2:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint16(b))
	case 4:
		return fmt.Sprintf("%d  (ip %s)", binary.LittleEndian.Uint32(b), net.IP(b).String())
	case 8:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint64(b))
	case 16:
		return fmt.Sprintf("ip6 %s", net.IP(b).String())
	}
	return ""
}

// shortDecode is a compact single-column rendering for tables.
func shortDecode(b []byte) string {
	switch len(b) {
	case 1, 2, 8:
		return decode(b)
	case 4:
		return fmt.Sprintf("%d", binary.LittleEndian.Uint32(b))
	}
	return ""
}

func sumPerCPU(vals [][]byte) (uint64, bool) {
	var total uint64
	for _, v := range vals {
		switch len(v) {
		case 4:
			total += uint64(binary.LittleEndian.Uint32(v))
		case 8:
			total += binary.LittleEndian.Uint64(v)
		default:
			return 0, false
		}
	}
	return total, true
}

func hexDump(b []byte) string {
	if len(b) == 0 {
		return "  (empty)\n"
	}
	return hex.Dump(b)
}

// lookupEntry re-reads a single key, returning one value per CPU (a single
// value for regular maps). Returns ebpf.ErrKeyNotExist if it was deleted.
func lookupEntry(id ebpf.MapID, key []byte) ([][]byte, error) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	return lookupIn(m, key)
}

// lookupIn is lookupEntry on an already open map.
func lookupIn(m *ebpf.Map, key []byte) ([][]byte, error) {
	if isPerCPU(m.Type()) {
		var vals [][]byte
		if err := m.Lookup(key, &vals); err != nil {
			return nil, err
		}
		return vals, nil
	}
	val, err := m.LookupBytes(key)
	if err != nil {
		return nil, err
	}
	if val == nil {
		return nil, ebpf.ErrKeyNotExist
	}
	return [][]byte{val}, nil
}
