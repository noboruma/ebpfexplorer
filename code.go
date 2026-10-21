package main

// The code view ([d] on a program): the program as the kernel runs it, after
// the verifier rewrote it ("xlated"), in bpftool's C-like syntax, each
// instruction next to the C line it was compiled from. The C text comes with
// the program itself: clang -g puts the source lines in the BTF line info.

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

var (
	codeLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("221"))
	codeSrcStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("114"))
	codeDimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

// codeRow is a line of the code view: a function label or an instruction.
type codeRow struct {
	off    int    // instruction offset, in 8-byte slots; -1 on labels
	label  string // function name, on labels
	raw    string // instruction bytes
	text   string
	src    string // "file.c:12  the line", where a new C line starts
	target int    // row a jump or call goes to, or -1
	note   string // what the instruction refers to, for the status line
}

type codeView struct {
	prog    progRow
	loading bool
	err     error
	info    string
	rows    []codeRow
	pane    pane
}

type codeLoaded struct {
	id   ebpf.ProgramID
	rows []codeRow
	info string
	err  error
}

func loadCodeCmd(p progRow) tea.Cmd {
	return func() tea.Msg {
		rows, info, err := readProgramCode(p)
		return codeLoaded{p.ID, rows, info, err}
	}
}

func readProgramCode(p progRow) ([]codeRow, string, error) {
	prog, err := ebpf.NewProgramFromID(p.ID)
	if err != nil {
		return nil, "", err
	}
	defer prog.Close()
	info, err := prog.Info()
	if err != nil {
		return nil, "", err
	}
	insns, err := info.Instructions()
	if err != nil {
		return nil, "", fmt.Errorf("reading the instructions (needs root): %w", err)
	}
	names := codeNames{kernel: true, maps: map[uint32]string{}}
	for _, r := range loadMaps(p.MapIDs) {
		names.maps[uint32(r.ID)] = r.Name
	}
	rows := buildCodeRows(insns, &names)

	parts := []string{fmt.Sprintf("%d instructions (xlated)", len(insns))}
	if n, err := info.JitedSize(); err == nil {
		parts = append(parts, fmt.Sprintf("JIT %d bytes", n))
	}
	if _, err := info.LineInfos(); err != nil {
		parts = append(parts, "no C source: the program has no BTF line info (built without clang -g)")
	} else {
		parts = append(parts, "C source from BTF line info")
	}
	return rows, strings.Join(parts, "  •  "), nil
}

// codeNames names what instructions refer to. Instructions read from the
// kernel (kernel set) hold map IDs and helper addresses; instructions from
// an ELF object hold references to symbols and helper numbers.
type codeNames struct {
	kernel bool
	maps   map[uint32]string // by ID

	ksyms     map[uint64]string // function addresses, read on first use
	callBase  uint64            // __bpf_call_base
	ksymsRead bool
	kernelBTF *btf.Spec // for kfuncs
	btfRead   bool
}

// helper names the function a helper call goes to.
func (n *codeNames) helper(imm int64) string {
	if !n.kernel {
		return helperName(asm.BuiltinFunc(imm))
	}
	// the verifier replaced the helper number by the function's address,
	// relative to __bpf_call_base
	n.readKsyms()
	if n.callBase != 0 {
		if name, ok := n.ksyms[n.callBase+uint64(int32(imm))]; ok {
			return name
		}
	}
	return fmt.Sprintf("helper%+d", imm)
}

func (n *codeNames) readKsyms() {
	if n.ksymsRead {
		return
	}
	n.ksymsRead = true
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return
	}
	defer f.Close()
	n.ksyms = map[uint64]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// ffffffff81234560 T name [module]
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 { // hidden by kptr_restrict
			continue
		}
		switch fields[2] {
		case "__bpf_call_base":
			n.callBase = addr
		}
		if t := fields[1]; t == "T" || t == "t" {
			if _, dup := n.ksyms[addr]; !dup {
				n.ksyms[addr] = fields[2]
			}
		}
	}
}

func (n *codeNames) kfunc(id int64) string {
	if !n.btfRead {
		n.btfRead = true
		n.kernelBTF, _ = btf.LoadKernelSpec()
	}
	if n.kernelBTF != nil {
		if t, err := n.kernelBTF.TypeByID(btf.TypeID(id)); err == nil && t.TypeName() != "" {
			return t.TypeName()
		}
	}
	return fmt.Sprintf("kfunc#%d", id)
}

// helperName spells FnMapLookupElem the C way: bpf_map_lookup_elem.
func helperName(f asm.BuiltinFunc) string {
	s, ok := strings.CutPrefix(f.String(), "Fn")
	if !ok {
		return fmt.Sprintf("helper#%d", uint32(f))
	}
	var b strings.Builder
	b.WriteString("bpf")
	prev := rune(0)
	for _, r := range s {
		if unicode.IsUpper(r) && (prev == 0 || unicode.IsLower(prev) || unicode.IsDigit(prev)) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
		prev = r
	}
	return b.String()
}

// hostOrder is binary.NativeEndian as one of the two orders asm can write.
var hostOrder binary.ByteOrder = binary.LittleEndian

func init() {
	if binary.NativeEndian.Uint16([]byte{0, 1}) == 1 {
		hostOrder = binary.BigEndian
	}
}

// sourceLine is the line info clang -g attaches to instructions (*btf.Line).
type sourceLine interface {
	FileName() string
	LineNumber() uint32
	Line() string
}

func buildCodeRows(insns asm.Instructions, names *codeNames) []codeRow {
	var rows []codeRow
	rowOf := map[int]int{}     // instruction offset → row
	symRow := map[string]int{} // function → its label row
	jumps := map[int]int{}     // row → instruction offset it jumps to
	calls := map[int]string{}  // row → function it calls, by name
	var lastFile string
	var lastLine uint32
	iter := insns.Iterate()
	for iter.Next() {
		ins, off := iter.Ins, int(iter.Offset)
		name := ins.Symbol()
		if fn := btf.FuncMetadata(ins); fn != nil && fn.Name != "" {
			name = fn.Name
		}
		if name != "" {
			symRow[name] = len(rows)
			rows = append(rows, codeRow{off: -1, label: name, target: -1})
			lastFile, lastLine = "", 0
		}
		row := codeRow{off: off, target: -1}
		row.text, row.note = bpfText(ins, names)
		var raw bytes.Buffer
		if _, err := ins.Marshal(&raw, hostOrder); err == nil {
			row.raw = hexBytes(raw.Bytes(), 0)
		}
		if sl, ok := ins.Source().(sourceLine); ok && (sl.FileName() != lastFile || sl.LineNumber() != lastLine) {
			lastFile, lastLine = sl.FileName(), sl.LineNumber()
			file := lastFile[strings.LastIndexByte(lastFile, '/')+1:]
			row.src = strings.TrimSpace(fmt.Sprintf("%s:%d  %s", file, lastLine, strings.TrimSpace(strings.ReplaceAll(sl.Line(), "\t", " "))))
		}
		op := ins.OpCode
		if op.Class().IsJump() {
			switch {
			case op.JumpOp() == asm.Call && ins.Src == asm.PseudoCall:
				if ref := ins.Reference(); ref != "" {
					calls[len(rows)] = ref
				} else {
					delta := ins.Constant
					if ins.Offset != 0 { // JIT-compiled: the kernel keeps it in off
						delta = int64(ins.Offset)
					}
					jumps[len(rows)] = off + 1 + int(delta)
				}
			case op.JumpOp() == asm.Ja && op.Class() == asm.Jump32Class:
				jumps[len(rows)] = off + 1 + int(ins.Constant)
			case op.JumpOp() != asm.Call && op.JumpOp() != asm.Exit:
				jumps[len(rows)] = off + 1 + int(ins.Offset)
			}
		}
		rowOf[off] = len(rows)
		rows = append(rows, row)
	}
	for r, off := range jumps {
		if t, ok := rowOf[off]; ok {
			rows[r].target = t
			if rows[r].note == "" {
				rows[r].note = fmt.Sprintf("jumps to %d", off)
			}
		}
	}
	for r, name := range calls {
		if t, ok := symRow[name]; ok {
			rows[r].target = t
		}
	}
	// name the callee of bpf-to-bpf calls by its label
	for r := range rows {
		if t := rows[r].target; t >= 0 && rows[t].off < 0 && strings.HasPrefix(rows[r].text, "call pc") {
			rows[r].text = "call " + rows[t].label
			rows[r].note = "calls " + rows[t].label
		}
	}
	return rows
}

var (
	aluOps = map[asm.ALUOp]string{
		asm.Add: "+=", asm.Sub: "-=", asm.Mul: "*=", asm.Div: "/=", asm.SDiv: "s/=", asm.Or: "|=", asm.And: "&=",
		asm.LSh: "<<=", asm.RSh: ">>=", asm.Mod: "%=", asm.SMod: "s%=", asm.Xor: "^=", asm.ArSh: "s>>=",
	}
	jumpOps = map[asm.JumpOp]string{
		asm.JEq: "==", asm.JGT: ">", asm.JGE: ">=", asm.JSet: "&", asm.JNE: "!=", asm.JSGT: "s>", asm.JSGE: "s>=",
		asm.JLT: "<", asm.JLE: "<=", asm.JSLT: "s<", asm.JSLE: "s<=",
	}
	sizeNames   = map[asm.Size]string{asm.Byte: "u8", asm.Half: "u16", asm.Word: "u32", asm.DWord: "u64"}
	atomicNames = map[asm.AtomicOp]string{
		asm.FetchAdd: "fetch_add", asm.FetchAnd: "fetch_and", asm.FetchOr: "fetch_or", asm.FetchXor: "fetch_xor",
		asm.Xchg: "xchg", asm.CmpXchg: "cmpxchg",
	}
)

// bpfText writes an instruction the way bpftool and the verifier log do:
// r2 = *(u32 *)(r1 +4), if r0 == 0x0 goto pc+3, call bpf_map_lookup_elem.
// note says what it refers to.
func bpfText(ins *asm.Instruction, names *codeNames) (text, note string) {
	op := ins.OpCode
	reg := func(r asm.Register, wide bool) string {
		if wide {
			return fmt.Sprintf("r%d", r) // r10, where cilium says rfp
		}
		return fmt.Sprintf("w%d", r)
	}
	r := func(r asm.Register) string { return reg(r, true) }
	mem := func(sign string, base asm.Register, off int16) string {
		return fmt.Sprintf("*(%s%s *)(%s %+d)", sign, strings.TrimPrefix(sizeNames[op.Size()], "u"), r(base), off)
	}
	cls := op.Class()
	switch {
	case op == asm.InvalidOpCode:
		return "(invalid)", ""

	case ins.IsLoadFromMap():
		id := uint32(ins.Constant)
		name := ins.Reference()
		if names.kernel {
			name = names.maps[id]
		}
		what := name
		switch {
		case name == "":
			what = fmt.Sprintf("map[id:%d]", id)
		case names.kernel:
			note = fmt.Sprintf("map %s (id %d)", name, id)
		default:
			note = "map " + name
		}
		if ins.Src == asm.PseudoMapValue {
			return fmt.Sprintf("%s = &%s[0] + %d", r(ins.Dst), what, uint32(ins.Constant>>32)), note
		}
		return fmt.Sprintf("%s = %s", r(ins.Dst), what), note

	case cls == asm.LdClass && op.Mode() == asm.ImmMode:
		return fmt.Sprintf("%s = %#x ll", r(ins.Dst), uint64(ins.Constant)), ""
	case cls == asm.LdClass && op.Mode() == asm.AbsMode:
		return fmt.Sprintf("r0 = *(%s *)skb[%d]", sizeNames[op.Size()], ins.Constant), ""
	case cls == asm.LdClass && op.Mode() == asm.IndMode:
		return fmt.Sprintf("r0 = *(%s *)skb[%s + %d]", sizeNames[op.Size()], r(ins.Src), ins.Constant), ""

	case cls == asm.LdXClass:
		sign := "u"
		if op.Mode() == asm.MemSXMode {
			sign = "s"
		}
		return fmt.Sprintf("%s = %s", r(ins.Dst), mem(sign, ins.Src, ins.Offset)), ""
	case cls == asm.StClass:
		return fmt.Sprintf("%s = %d", mem("u", ins.Dst, ins.Offset), ins.Constant), ""
	case cls == asm.StXClass && op.Mode() == asm.AtomicMode:
		a := op.AtomicOp()
		for _, simple := range []asm.AtomicOp{asm.AddAtomic, asm.AndAtomic, asm.OrAtomic, asm.XorAtomic} {
			if a == simple {
				return fmt.Sprintf("lock %s %s %s", mem("u", ins.Dst, ins.Offset), aluOps[asm.ALUOp(a>>8)], r(ins.Src)), ""
			}
		}
		fn, ok := atomicNames[a]
		if !ok {
			fn = strings.ToLower(a.String())
		}
		width := "atomic"
		if op.Size() == asm.DWord {
			width = "atomic64"
		}
		ptr := fmt.Sprintf("(%s *)(%s %+d)", sizeNames[op.Size()], r(ins.Dst), ins.Offset)
		if a == asm.CmpXchg {
			return fmt.Sprintf("r0 = %s_%s(%s, r0, %s)", width, fn, ptr, r(ins.Src)), ""
		}
		return fmt.Sprintf("%s = %s_%s(%s, %s)", r(ins.Src), width, fn, ptr, r(ins.Src)), ""
	case cls == asm.StXClass:
		return fmt.Sprintf("%s = %s", mem("u", ins.Dst, ins.Offset), r(ins.Src)), ""

	case cls.IsALU():
		wide := cls == asm.ALU64Class
		dst := reg(ins.Dst, wide)
		src := fmt.Sprint(ins.Constant)
		if op.Source() == asm.RegSource {
			src = reg(ins.Src, wide)
		}
		switch a := op.ALUOp(); a {
		case asm.Mov:
			return fmt.Sprintf("%s = %s", dst, src), ""
		case asm.MovSX8, asm.MovSX16, asm.MovSX32:
			bits := map[asm.ALUOp]int{asm.MovSX8: 8, asm.MovSX16: 16, asm.MovSX32: 32}[a]
			return fmt.Sprintf("%s = (s%d)%s", dst, bits, src), ""
		case asm.Neg:
			return fmt.Sprintf("%s = -%s", dst, dst), ""
		case asm.Swap:
			kind := "le"
			switch {
			case wide:
				kind = "bswap"
			case op.Endianness() == asm.BE:
				kind = "be"
			}
			return fmt.Sprintf("%s = %s%d %s", r(ins.Dst), kind, ins.Constant, r(ins.Dst)), ""
		default:
			if s, ok := aluOps[a]; ok {
				return fmt.Sprintf("%s %s %s", dst, s, src), ""
			}
		}

	case cls.IsJump():
		switch j := op.JumpOp(); j {
		case asm.Exit:
			return "exit", ""
		case asm.Call:
			switch ins.Src {
			case asm.PseudoCall:
				if ref := ins.Reference(); ref != "" {
					return "call " + ref, "calls " + ref
				}
				delta := ins.Constant
				if ins.Offset != 0 {
					delta = int64(ins.Offset)
				}
				return fmt.Sprintf("call pc%+d", delta), ""
			case asm.PseudoKfuncCall:
				name := names.kfunc(ins.Constant)
				return "call " + name, "calls kfunc " + name
			}
			name := names.helper(ins.Constant)
			return "call " + name, "calls helper " + name
		case asm.Ja:
			if cls == asm.Jump32Class {
				return fmt.Sprintf("gotol pc%+d", ins.Constant), ""
			}
			return fmt.Sprintf("goto pc%+d", ins.Offset), ""
		case asm.JCOND:
			return fmt.Sprintf("may_goto pc%+d", ins.Offset), ""
		default:
			wide := cls == asm.JumpClass
			src := fmt.Sprintf("%#x", ins.Constant)
			if op.Source() == asm.RegSource {
				src = reg(ins.Src, wide)
			}
			return fmt.Sprintf("if %s %s %s goto pc%+d", reg(ins.Dst, wide), jumpOps[j], src, ins.Offset), ""
		}
	}
	return fmt.Sprint(*ins), "" // anything else: cilium's own spelling
}

// --- the view ---

func (m model) openCode(p progRow) (tea.Model, tea.Cmd) {
	m.code = &codeView{prog: p, loading: true}
	return m, loadCodeCmd(p)
}

func (m model) updateCode(key string) (tea.Model, tea.Cmd) {
	c := m.code
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "esc", "backspace":
		m.code = nil
		return m, nil
	case "left", "h":
		if c.pane.hOff == 0 {
			m.code = nil
			return m, nil
		}
		c.pane.hOff = max(0, c.pane.hOff-hStep)
		return m, nil
	case "right", "l":
		t := m.codeTable()
		c.pane.hOff = min(c.pane.hOff+hStep, t.overflow(c.pane, m.codeRows()))
		return m, nil
	case "r":
		return m.openCode(c.prog)
	case "enter":
		if c.pane.cur < len(c.rows) {
			if t := c.rows[c.pane.cur].target; t >= 0 {
				c.pane.cur = t
				c.pane.off = max(0, t-m.codeRows()/3)
				c.pane.clamp(len(c.rows), m.codeRows())
			}
		}
		return m, nil
	}
	c.pane.move(key, len(c.rows), m.codeRows())
	return m, nil
}

func (m model) codeHeader() []string {
	c := m.code
	name := c.prog.Name
	if name == "" {
		name = "<anon>"
	}
	lines := []string{labelStyle.Render(fmt.Sprintf("prog %d %s", c.prog.ID, name)) +
		crumbStyle.Render(fmt.Sprintf("  %s  tag %s", c.prog.Type, c.prog.Tag))}
	if c.info != "" {
		lines = append(lines, crumbStyle.Render(c.info))
	}
	return lines
}

// codeRows is how many rows fit under the header and the column titles.
func (m model) codeRows() int {
	return max(2, m.height-3-len(m.codeHeader())-2)
}

func (m model) codeTable() tableSpec {
	c := m.code
	w := max(20, m.width-2)
	empty := "(no instructions)"
	switch {
	case c.loading:
		empty = "loading…"
	case c.err != nil:
		empty = "" // the status line says why
	}
	specs := []colSpec{{"#", 5, 0}, {"Bytes", 23, 0}, {"Instruction", 34, 1}, {"C source", 24, 3}}
	row := func(r int) []string {
		cr := c.rows[r]
		if cr.off < 0 {
			return []string{"", "", cr.label + ":", ""}
		}
		return []string{strconv.Itoa(cr.off), cr.raw, cr.text, cr.src}
	}
	paint := func(r, col int, s string) string {
		title := specs[col].title
		switch {
		case c.rows[r].off < 0:
			return codeLabelStyle.Render(s)
		case title == "C source":
			return codeSrcStyle.Render(s)
		case title == "Bytes" || title == "#":
			return codeDimStyle.Render(s)
		}
		return s
	}
	return tableSpec{cols: fitColumns(w, specs), n: len(c.rows), row: row, empty: empty, paint: paint}
}

func (m model) codeContent() string {
	c := m.code
	var body []string
	width := max(10, m.width-1)
	for _, l := range m.codeHeader() {
		body = append(body, scrollLine(l, 0, width))
	}
	body = append(body, m.codeTable().render(c.pane, m.codeRows()))
	return strings.Join(body, "\n")
}

func (m model) codeStatus() string {
	c := m.code
	switch {
	case c.loading:
		return "disassembling…"
	case len(c.rows) == 0:
		return ""
	}
	parts := []string{fmt.Sprintf("row %d/%d", c.pane.cur+1, len(c.rows))}
	if cr := c.rows[c.pane.cur]; cr.note != "" {
		s := cr.note
		if cr.target >= 0 {
			s += " [enter]"
		}
		parts = append(parts, s)
	}
	if c.pane.hOff > 0 {
		parts = append(parts, fmt.Sprintf("scrolled →%d", c.pane.hOff))
	}
	return strings.Join(parts, " • ")
}

func (m model) codeHelp() [][2]string {
	return [][2]string{{"↑/↓ pgup/pgdn g/G", "move"}, {"←/→", "scroll"}, {"enter", "follow jump/call"}, {"esc", "back"}, {"r", "reload"}, {"q", "quit"}}
}
