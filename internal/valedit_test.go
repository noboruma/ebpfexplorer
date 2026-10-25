package internal

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
)

// TestParseRoundTrip: what formatValue prints, parse reads back.
func TestParseRoundTrip(t *testing.T) {
	v, err := parseCType(`struct { __u32 a; __s16 b; __be16 port; char c; bool ok; ipv4 ip; ipv6 ip6; mac hw;
		char name[8]; __u8 raw[4]; __u16 arr[3]; x32 flags; double d; }`)
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]string{
		"a": "4000000000", "b": "-12", "port": "443", "c": "'x'", "ok": "true", "ip": "10.0.0.1",
		"ip6": "fe80::1", "hw": "aa:bb:cc:dd:ee:ff", "name": `"eth0"`, "raw": "0xdeadbeef",
		"arr": "[1 2 3]", "flags": "0x1f", "d": "1.5",
	}
	b := make([]byte, v.size)
	for _, l := range v.leaves("", 0) {
		if err := l.t.parse(in[l.path], b[l.off:][:l.t.size]); err != nil {
			t.Fatalf("%s: %v", l.path, err)
		}
	}
	for _, l := range v.leaves("", 0) {
		if got := l.t.formatValue(b[l.off:][:l.t.size]); got != in[l.path] {
			t.Errorf("%s: %q, want %q", l.path, got, in[l.path])
		}
	}

	u8 := intType(1, false)
	for _, bad := range []string{"256", "-1", "x"} {
		if err := u8.parse(bad, make([]byte, 1)); err == nil {
			t.Errorf("u8 %q: no error", bad)
		}
	}
	if err := v.leaves("", 0)[8].t.parse(`"far too long"`, make([]byte, 8)); err == nil {
		t.Error("a string longer than the array must fail")
	}
}

func valModel(t *testing.T, typ ebpf.MapType, ncpu int, vals []byte, format string) model {
	t.Helper()
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 110, Height: 30})
	m = next.(model)
	m.view = viewEntries
	m.allowWrite = true
	m.loadGen = 3
	size := len(vals) / ncpu
	m.curMap = mapRow{ID: 7, Name: "stats", Type: typ, KeySize: 4, ValueSize: uint32(size)}
	m.store = entryStore{keySize: 4, valSize: size, ncpu: ncpu}
	m.store.append(&chunk{n: 1, keys: le32(9), vals: vals})
	if format != "" {
		v, err := parseCType(format)
		if err != nil {
			t.Fatal(err)
		}
		m.formats.compiled["stats"] = compiledFormat{value: v}
	}
	return m
}

// typeIn types s into the focused input, replacing it.
func typeIn(m model, s string) model {
	m.valEdit.inputs[m.valEdit.focus].SetValue(s)
	return m
}

func TestWriteEntryFields(t *testing.T) {
	m := valModel(t, ebpf.Hash, 1, cat(le64(12), le64(1600)), "struct { __u64 packets; __u64 bytes; }")
	m = press(m, "w")
	e := m.valEdit
	if e == nil || len(e.inputs) != 2 || e.inputs[0].Value() != "12" || e.inputs[1].Value() != "1600" {
		t.Fatalf("w opens the fields with their values: %+v", e)
	}
	if out := m.View(); !strings.Contains(out, "packets u64") || !strings.Contains(out, "Write map 7") {
		t.Fatalf("editor view:\n%s", out)
	}
	if m = press(m, "enter"); m.valEdit.confirm || m.valEdit.err != "nothing changed" {
		t.Fatal("nothing changed: no write")
	}
	m = press(m, "down")
	m = typeIn(m, "nope")
	if m = press(m, "enter"); m.valEdit.confirm || !strings.Contains(m.valEdit.errs[1], "not a u64") {
		t.Fatalf("a bad field blocks the write: %q", m.valEdit.errs)
	}
	m = typeIn(m, "0")
	if m = press(m, "enter"); !m.valEdit.confirm || !strings.Contains(m.View(), "write 1 changed field(s)") {
		t.Fatalf("enter asks first:\n%s", m.View())
	}
	vals, _, _ := m.valEdit.build()
	if !bytes.Equal(vals[0], cat(le64(12), le64(0))) {
		t.Fatalf("value = % x", vals[0])
	}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	if m = next.(model); cmd == nil || !m.valEdit.writing {
		t.Fatal("y writes")
	}

	next, cmd = m.Update(entryWritten{gen: 3, idx: 0, err: ebpf.ErrKeyNotExist})
	if m = next.(model); m.valEdit == nil || !strings.Contains(m.valEdit.err, "key does not exist") {
		t.Fatal("a failed write stays in the editor with the error")
	}
	next, cmd = m.Update(entryWritten{gen: 3, idx: 0})
	if m = next.(model); m.valEdit != nil || cmd == nil || !strings.Contains(m.status(), "wrote entry #0") {
		t.Fatalf("a write closes the editor and reads the entry back: %q", m.status())
	}
}

func TestWriteEntryHexAndCPUs(t *testing.T) {
	// no format: the value's hex
	m := valModel(t, ebpf.Array, 1, le32(5), "")
	m = press(m, "w")
	if got := m.valEdit.inputs[0].Value(); got != "05 00 00 00" {
		t.Fatalf("hex input %q", got)
	}
	m = typeIn(m, "01 02")
	if m = press(m, "enter"); !strings.Contains(m.valEdit.errs[0], "2 bytes, the value is 4") {
		t.Fatalf("errs %q", m.valEdit.errs)
	}
	m = typeIn(m, "0x2a000000")
	if vals, n, ok := m.valEdit.build(); !ok || n != 1 || !bytes.Equal(vals[0], le32(42)) {
		t.Fatalf("hex write: % x", vals)
	}

	// per-CPU, from the list: all CPUs; fields that differ start empty
	format := "struct { __u64 count; __u64 limit; }"
	m = valModel(t, ebpf.PerCPUArray, 2, cat(le64(1), le64(100), le64(2), le64(100)), format)
	m = press(m, "w")
	e := m.valEdit
	if e.cpu != -1 || e.inputs[0].Value() != "" || e.inputs[1].Value() != "100" {
		t.Fatalf("all CPUs: count differs, limit agrees: %q %q", e.inputs[0].Value(), e.inputs[1].Value())
	}
	m = press(m, "down")
	m = typeIn(m, "50")
	vals, _, _ := m.valEdit.build()
	if !slices.EqualFunc(vals, [][]byte{cat(le64(1), le64(50)), cat(le64(2), le64(50))}, bytes.Equal) {
		t.Fatalf("each CPU keeps its count: % x", vals)
	}

	// from the CPU table: that CPU only
	m = valModel(t, ebpf.PerCPUArray, 2, cat(le64(1), le64(100), le64(2), le64(100)), format)
	m = press(m, "enter", "j", "j", "w") // Σ, cpu0, cpu1
	if m.valEdit == nil || m.valEdit.cpu != 1 || m.valEdit.inputs[0].Value() != "2" {
		t.Fatalf("w on the cpu1 row writes cpu1: %+v", m.valEdit)
	}
	m = typeIn(m, "0")
	vals, _, _ = m.valEdit.build()
	if !bytes.Equal(vals[0], cat(le64(1), le64(100))) || !bytes.Equal(vals[1], cat(le64(0), le64(100))) {
		t.Fatalf("only cpu1 changes: % x", vals)
	}
}

func TestWriteNotEditable(t *testing.T) {
	m := valModel(t, ebpf.ProgramArray, 1, le32(3), "")
	if m = press(m, "w"); m.valEdit != nil || m.err == nil {
		t.Fatal("program array values are fds: no editor")
	}
}

func TestWriteNeedsFlag(t *testing.T) {
	m := valModel(t, ebpf.Hash, 1, le32(5), "")
	m.allowWrite = false
	if strings.Contains(m.help(), "[w]") {
		t.Error("no [w] in the help without --allow-write")
	}
	if m = press(m, "w"); m.valEdit != nil || !strings.Contains(m.status(), "--allow-write") {
		t.Fatalf("w is refused without --allow-write: %q", m.status())
	}
	m.allowWrite = true
	if !strings.Contains(m.help(), "[w] write") {
		t.Error("[w] in the help with --allow-write")
	}
}
