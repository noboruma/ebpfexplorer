package internal

// Writing a map entry ([w] on an entry): one input per field of the value's
// format, or the value's hex without one, then BPF_MAP_UPDATE_ELEM. Only the
// fields changed are written: the rest of the value keeps the bytes read.
// Per-CPU maps are written for one CPU (picked in the entry's CPU table) or
// for all of them.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/cilium/ebpf"
)

type valEditor struct {
	mp     mapRow
	idx    int // store index of the entry
	gen    int // loadGen when opened: the store must still be the same
	key    []byte
	vals   [][]byte // as read, one per CPU
	cpu    int      // the CPU written, -1 for every CPU (or a regular map)
	t      *ctype   // value format; nil edits the hex
	leaves []leaf   // one per input, with t
	inputs []textinput.Model
	orig   []string // what each input started with
	errs   []string
	focus  int

	confirm bool // the new value is checked: waiting for y
	writing bool
	err     string
}

type entryWritten struct {
	gen, idx int
	err      error
}

// notEditable says why values of a map type can't be written here.
func notEditable(t ebpf.MapType) string {
	switch t {
	case ebpf.ProgramArray, ebpf.ArrayOfMaps, ebpf.HashOfMaps, ebpf.SockMap, ebpf.SockHash, ebpf.XSKMap,
		ebpf.ReusePortSockArray, ebpf.PerfEventArray, ebpf.CGroupArray:
		return fmt.Sprintf("values of a %s are file descriptors, they can't be written here", t)
	case ebpf.RingBuf, ebpf.UserRingbuf, ebpf.Queue, ebpf.Stack, ebpf.BloomFilter, ebpf.StackTrace:
		return fmt.Sprintf("a %s has no entries to write", t)
	}
	return ""
}

// openValEditor edits entry idx of the current map; cpu as for valEditor.
func (m *model) openValEditor(idx, cpu int) {
	if why := notEditable(m.curMap.Type); why != "" {
		m.err = errors.New(why)
		return
	}
	_, vf := m.activeFormats()
	e := &valEditor{mp: m.curMap, idx: idx, gen: m.loadGen, cpu: cpu, t: vf,
		key: slices.Clone(m.store.key(idx))}
	for _, v := range m.store.values(idx) {
		e.vals = append(e.vals, slices.Clone(v))
	}
	if vf != nil {
		e.leaves = vf.leaves("", 0)
	} else {
		e.leaves = []leaf{{off: 0, t: nil}}
	}
	for _, l := range e.leaves {
		in := textinput.New()
		in.Prompt = ""
		in.CharLimit = 4096
		v, same := e.current(l)
		if same {
			in.SetValue(v)
		} else {
			in.Placeholder = "differs per CPU: empty keeps each CPU's value"
		}
		e.inputs = append(e.inputs, in)
		e.orig = append(e.orig, in.Value())
	}
	e.errs = make([]string, len(e.inputs))
	e.inputs[0].Focus()
	m.valEdit = e
}

// targets are the CPUs written.
func (e *valEditor) targets() []int {
	if e.cpu >= 0 {
		return []int{e.cpu}
	}
	cpus := make([]int, len(e.vals))
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

// current is the text of leaf l in the CPUs written, and whether they all
// agree on it.
func (e *valEditor) current(l leaf) (string, bool) {
	text := func(v []byte) string {
		if l.t == nil {
			return hexBytes(v, 0)
		}
		return l.t.formatValue(v[l.off:][:l.t.size])
	}
	cpus := e.targets()
	first := text(e.vals[cpus[0]])
	for _, c := range cpus[1:] {
		if text(e.vals[c]) != first {
			return "", false
		}
	}
	return first, true
}

// build checks the inputs and returns the values to write, and how many
// fields change.
func (e *valEditor) build() ([][]byte, int, bool) {
	out := make([][]byte, len(e.vals))
	for i, v := range e.vals {
		out[i] = slices.Clone(v)
	}
	ok, changed := true, 0
	for i, l := range e.leaves {
		e.errs[i] = ""
		s := strings.TrimSpace(e.inputs[i].Value())
		if s == "" || s == e.orig[i] {
			continue
		}
		field := make([]byte, len(e.vals[0]))
		var err error
		if l.t == nil {
			field, err = parseHex(s, len(field))
		} else {
			field = field[:l.t.size]
			err = l.t.parse(s, field)
		}
		if err != nil {
			e.errs[i], ok = err.Error(), false
			continue
		}
		changed++
		for _, c := range e.targets() {
			copy(out[c][l.off:], field)
		}
	}
	return out, changed, ok
}

func parseHex(s string, size int) ([]byte, error) {
	s = strings.TrimPrefix(strings.Join(strings.Fields(s), ""), "0x")
	b, err := hex.DecodeString(s)
	switch {
	case err != nil:
		return nil, fmt.Errorf("not hex: %v", err)
	case len(b) != size:
		return nil, fmt.Errorf("%d bytes, the value is %d", len(b), size)
	}
	return b, nil
}

func writeEntryCmd(mp mapRow, key []byte, vals [][]byte, gen, idx int) tea.Cmd {
	return func() tea.Msg {
		m, err := ebpf.NewMapFromID(mp.ID)
		if err != nil {
			return entryWritten{gen, idx, err}
		}
		defer m.Close()
		var value any = vals[0]
		if isPerCPU(mp.Type) {
			value = vals
		}
		// UpdateExist: a key deleted meanwhile is not created again
		if err := m.Update(key, value, ebpf.UpdateExist); err != nil {
			return entryWritten{gen, idx, fmt.Errorf("writing the entry: %w", err)}
		}
		return entryWritten{gen, idx, nil}
	}
}

func (m model) onEntryWritten(msg entryWritten) (tea.Model, tea.Cmd) {
	e := m.valEdit
	if e == nil || msg.gen != e.gen || msg.idx != e.idx {
		return m, nil
	}
	e.writing = false
	if msg.err != nil {
		e.confirm, e.err = false, msg.err.Error()
		return m, nil
	}
	m.valEdit = nil
	m.notice = fmt.Sprintf("wrote entry #%d", msg.idx)
	// read it back: what the kernel holds now
	m.entryReload = true
	return m, refreshEntryCmd(m.curMap.ID, e.key, msg.idx, m.loadGen)
}

func (m model) updateValEditor(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := m.valEdit
	if e.writing {
		return m, nil
	}
	if e.confirm {
		switch msg.String() {
		case "y":
			vals, _, _ := e.build()
			e.writing = true
			return m, writeEntryCmd(e.mp, e.key, vals, e.gen, e.idx)
		case "ctrl+c":
			return m, tea.Quit
		default:
			e.confirm = false
		}
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.valEdit = nil
		return m, nil
	case "up", "shift+tab":
		e.setFocus(e.focus - 1)
		return m, textinput.Blink
	case "down", "tab":
		e.setFocus(e.focus + 1)
		return m, textinput.Blink
	case "enter":
		e.err = ""
		_, changed, ok := e.build()
		switch {
		case !ok:
		case changed == 0:
			e.err = "nothing changed"
		default:
			e.confirm = true
		}
		return m, nil
	}
	var cmd tea.Cmd
	e.inputs[e.focus], cmd = e.inputs[e.focus].Update(msg)
	return m, cmd
}

func (e *valEditor) setFocus(f int) {
	e.inputs[e.focus].Blur()
	e.focus = (f + len(e.inputs)) % len(e.inputs)
	e.inputs[e.focus].Focus()
}

func (e *valEditor) target() string {
	switch {
	case !isPerCPU(e.mp.Type):
		return ""
	case e.cpu >= 0:
		return fmt.Sprintf(" on CPU %d", e.cpu)
	}
	return fmt.Sprintf(" on all %d CPUs", len(e.vals))
}

func (e *valEditor) view(width, height int) string {
	var lines []string
	lines = append(lines,
		labelStyle.Render(fmt.Sprintf("Write map %d %q entry #%d", e.mp.ID, e.mp.Name, e.idx))+crumbStyle.Render(e.target()),
		crumbStyle.Render("key: "+hexBytes(e.key, 0)),
		"")
	labelW := 0
	for _, l := range e.leaves {
		labelW = max(labelW, ansi.StringWidth(e.label(l)))
	}
	labelW = min(labelW, width/3)
	inputW := max(10, width-labelW-4)
	var fields []string
	focusLine := 0
	for i, l := range e.leaves {
		if i == e.focus {
			focusLine = len(fields)
		}
		in := e.inputs[i]
		in.Width = inputW
		mark := "  "
		if i == e.focus {
			mark = "› "
		}
		fields = append(fields, mark+labelStyle.Render(cell(e.label(l), labelW))+" "+in.View())
		if e.errs[i] != "" {
			fields = append(fields, "  "+strings.Repeat(" ", labelW+3)+errStyle.Render(e.errs[i]))
		}
	}
	room := max(1, height-len(lines)-2)
	off := max(0, min(focusLine-room+2, len(fields)-room))
	lines = append(lines, fields[off:min(len(fields), off+room)]...)
	lines = append(lines, "")
	switch {
	case e.writing:
		lines = append(lines, statusStyle.Render("writing…"))
	case e.confirm:
		_, n, _ := e.build()
		lines = append(lines, statusStyle.Render(fmt.Sprintf("write %d changed field(s) to the map%s? [y] write  [any key] back", n, e.target())))
	case e.err != "":
		lines = append(lines, errStyle.Render(e.err))
	}
	return strings.Join(lines, "\n")
}

func (e *valEditor) label(l leaf) string {
	if l.t == nil {
		return fmt.Sprintf("value (%d bytes hex)", len(e.vals[0]))
	}
	p := l.path
	if p == "" {
		p = "value"
	}
	return p + " " + l.t.typeName()
}

func (e *valEditor) help() [][2]string {
	return [][2]string{{"↑/↓ tab", "field"}, {"enter", "write"}, {"esc", "cancel"}}
}

// typeName spells a leaf's type, as a hint next to its input.
func (t *ctype) typeName() string {
	switch t.kind {
	case kInt:
		switch {
		case t.char:
			return "char"
		case t.hex:
			return fmt.Sprintf("x%d", 8*t.size)
		case t.bigEndian:
			return fmt.Sprintf("be%d", 8*t.size)
		case t.signed:
			return fmt.Sprintf("s%d", 8*t.size)
		}
		return fmt.Sprintf("u%d", 8*t.size)
	case kBool:
		return "bool"
	case kFloat:
		if t.size == 4 {
			return "float"
		}
		return "double"
	case kPtr:
		return "ptr"
	case kIP4:
		return "ipv4"
	case kIP6:
		return "ipv6"
	case kMAC:
		return "mac"
	case kArray:
		return fmt.Sprintf("%s[%d]", t.elem.typeName(), t.n)
	}
	return "struct"
}

// parse is formatValue backwards: it writes the value s spells into b
// (t.size bytes). It takes what formatValue prints, and the usual spellings
// of numbers (0x1f, -3).
func (t *ctype) parse(s string, b []byte) error {
	s = strings.TrimSpace(s)
	bad := func() error { return fmt.Errorf("not a %s: %q", t.typeName(), s) }
	switch t.kind {
	case kInt:
		if t.char {
			if r, err := strconv.Unquote(s); err == nil && len(r) == 1 {
				b[0] = r[0]
				return nil
			}
		}
		bits := 8 * t.size
		if t.signed {
			v, err := strconv.ParseInt(s, 0, bits)
			if err != nil {
				return bad()
			}
			t.putUint(b, uint64(v))
			return nil
		}
		v, err := strconv.ParseUint(s, 0, bits)
		if err != nil {
			return bad()
		}
		t.putUint(b, v)
	case kBool:
		v, err := strconv.ParseBool(s)
		if err != nil {
			return bad()
		}
		clear(b)
		if v {
			b[0] = 1
		}
	case kFloat:
		v, err := strconv.ParseFloat(s, 8*t.size)
		if err != nil {
			return bad()
		}
		if t.size == 4 {
			binary.NativeEndian.PutUint32(b, math.Float32bits(float32(v)))
		} else {
			binary.NativeEndian.PutUint64(b, math.Float64bits(v))
		}
	case kPtr:
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return bad()
		}
		binary.NativeEndian.PutUint64(b, v)
	case kIP4:
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return bad()
		}
		copy(b, ip)
	case kIP6:
		ip := net.ParseIP(s)
		if ip == nil {
			return bad()
		}
		copy(b, ip.To16())
	case kMAC:
		mac, err := net.ParseMAC(s)
		if err != nil || len(mac) != 6 {
			return bad()
		}
		copy(b, mac)
	case kArray:
		return t.parseArray(s, b)
	default:
		return fmt.Errorf("a %s can't be written as one field", t.typeName())
	}
	return nil
}

func (t *ctype) parseArray(s string, b []byte) error {
	e := t.elem
	switch {
	case e.kind == kInt && e.char: // a string
		if q, err := strconv.Unquote(s); err == nil {
			s = q
		}
		if len(s) > t.n {
			return fmt.Errorf("%d bytes, the field holds %d", len(s), t.n)
		}
		clear(b)
		copy(b, s)
		return nil
	case e.kind == kInt && e.size == 1 && !e.signed: // bytes, as hex
		v, err := parseHex(s, t.n)
		if err != nil {
			return err
		}
		copy(b, v)
		return nil
	}
	parts := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
	if len(parts) != t.n {
		return fmt.Errorf("%d elements, the array has %d: [a b …]", len(parts), t.n)
	}
	var out bytes.Buffer
	for i, p := range parts {
		eb := make([]byte, e.size)
		if err := e.parse(p, eb); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
		out.Write(eb)
	}
	copy(b, out.Bytes())
	return nil
}
