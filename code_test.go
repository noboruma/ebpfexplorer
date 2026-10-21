package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// compiledProg builds testdata/prog.c with clang and returns the code rows
// of its XDP program, read from the object file.
func compiledProg(t *testing.T) []codeRow {
	t.Helper()
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("needs clang")
	}
	obj := filepath.Join(t.TempDir(), "prog.o")
	if out, err := exec.Command("clang", "-O2", "-g", "-target", "bpf", "-c", "testdata/prog.c", "-o", obj).CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	return buildCodeRows(spec.Programs["count_packets"].Instructions, &codeNames{})
}

func TestCodeRows(t *testing.T) {
	rows := compiledProg(t)
	var all []string
	for _, r := range rows {
		all = append(all, strings.Join([]string{r.label, r.raw, r.text, r.src, r.note}, " | "))
	}
	dump := strings.Join(all, "\n")
	t.Log("\n" + dump)
	for _, want := range []string{
		"count_packets |", // label
		"call bpf_map_lookup_elem",
		"call bpf_map_update_elem",
		"= counts",                                    // map load
		"prog.c:31",                                   // C line of the lookup
		"bpf_map_lookup_elem(&counts, &key)",          // its text, from BTF
		"r6 = atomic64_fetch_add((u64 *)(r0 +0), r6)", // __sync_fetch_and_add
		"*(u32 *)(r10 -4) = r0",
		"exit",
		"b4 00 00 00 02 00 00 00", // w0 = 2
		"map counts",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("missing %q", want)
		}
	}
	// jumps land on an instruction
	jumped := false
	for i, r := range rows {
		if strings.HasPrefix(r.text, "if ") {
			if r.target < 0 || rows[r.target].off < 0 {
				t.Errorf("row %d %q: bad target %d", i, r.text, r.target)
			}
			jumped = true
		}
	}
	if !jumped {
		t.Error("no conditional jump")
	}
}

func TestHelperName(t *testing.T) {
	for f, want := range map[uint32]string{1: "bpf_map_lookup_elem", 10: "bpf_l3_csum_replace", 14: "bpf_get_current_pid_tgid"} {
		if got := helperName(asmFunc(f)); got != want {
			t.Errorf("%d: %q, want %q", f, got, want)
		}
	}
}

func TestCodeView(t *testing.T) {
	rows := compiledProg(t)
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m = next.(model)
	m.progs = []progRow{{ID: 41, Name: "count_packets", Type: ebpf.XDP, Tag: "a1b2"}}
	m.progsLoading = false
	m.applyProgFilter()

	m = press(m, "d")
	if m.code == nil || !m.code.loading {
		t.Fatal("d opens the code view, loading")
	}
	next, _ = m.Update(codeLoaded{id: 41, rows: rows, info: "test"})
	m = next.(model)
	out := m.View()
	for _, want := range []string{"prog 41 count_packets", "Bytes", "C source", "Instruction", "85 00 00 00 01 00 00 00", "count_packets:", "bpf_map_lookup_elem"} {
		if !strings.Contains(out, want) {
			t.Errorf("view lacks %q:\n%s", want, out)
		}
	}

	// enter follows a jump
	for m.code.pane.cur < len(rows) && !strings.HasPrefix(rows[m.code.pane.cur].text, "if ") {
		m = press(m, "j")
	}
	want := rows[m.code.pane.cur].target
	if m = press(m, "enter"); m.code.pane.cur != want {
		t.Fatalf("enter: cursor %d, want %d", m.code.pane.cur, want)
	}

	if m = press(m, "esc"); m.code != nil || m.view != viewProgs {
		t.Fatal("esc closes the code view")
	}
}

func asmFunc(n uint32) asm.BuiltinFunc { return asm.BuiltinFunc(n) }
