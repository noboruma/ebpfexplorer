package internal

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/cilium/ebpf"
)

// mkChunk builds a chunk of 4-byte keys and 1-byte values from ints.
func mkChunk(keys ...[]byte) *chunk {
	c := &chunk{n: len(keys)}
	for i, k := range keys {
		c.keys = append(c.keys, k...)
		c.vals = append(c.vals, byte(i))
	}
	return c
}

// runSearch performs what Update does for a search: apply + run the scan.
func runSearch(t *testing.T, m *model, q string) {
	t.Helper()
	m.keyFilter.SetValue(q)
	cmd := m.applyKeyFilter()
	if cmd == nil {
		return
	}
	res, ok := cmd().(searchDone)
	if !ok {
		t.Fatalf("%q: search was cancelled", q)
	}
	next, _ := m.Update(res)
	*m = next.(model)
}

func TestKeySearch(t *testing.T) {
	m := initialModel(false)
	m.curMap = mapRow{Type: ebpf.Hash}
	m.store = entryStore{keySize: 4, valSize: 1, ncpu: 1}
	m.store.append(mkChunk([]byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}))
	m.store.append(mkChunk([]byte{192, 168, 1, 1}))

	for _, tc := range []struct {
		q    string
		want []int
	}{
		{"", []int{0, 1, 2}},
		{"0a000001", []int{0}},
		{"0a 00 00 02", []int{1}},
		{"10.0.0.", []int{0, 1}},
		{"192.168.1.1", []int{2}},
		{"C0A8", []int{2}},
		{"ffff", nil},
	} {
		runSearch(t, &m, tc.q)
		var got []int
		for r := range m.visCount() {
			got = append(got, m.visAt(r))
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.q, got, tc.want)
		}
	}
}

func TestChunksArrivingDuringSearch(t *testing.T) {
	m := initialModel(false)
	m.view = viewEntries
	m.curMap = mapRow{Type: ebpf.Hash}
	m.loadGen = 1
	m.store = entryStore{keySize: 4, valSize: 1, ncpu: 1}
	m.store.append(mkChunk([]byte{10, 0, 0, 1}))

	// Start a search but deliver a new chunk before its result arrives.
	m.keyFilter.SetValue("10.0.0")
	scan := m.applyKeyFilter()
	next, _ := m.Update(chunkLoaded{gen: 1, chunk: mkChunk([]byte{10, 0, 0, 9}, []byte{1, 1, 1, 1})})
	m = next.(model)
	next, _ = m.Update(scan())
	m = next.(model)

	if got := m.visible; !slices.Equal(got, []int32{0, 1}) {
		t.Fatalf("visible = %v, want [0 1] (match from late chunk must be caught up)", got)
	}
	if m.searching || m.loading {
		t.Fatalf("searching=%v loading=%v, want both false", m.searching, m.loading)
	}

	// A chunk from a stale load generation must be ignored.
	next, _ = m.Update(chunkLoaded{gen: 0, chunk: mkChunk([]byte{10, 0, 0, 7})})
	if next.(model).store.total != 3 {
		t.Fatalf("stale chunk was appended")
	}
}

func TestSupersededSearchCancels(t *testing.T) {
	m := initialModel(false)
	m.store = entryStore{keySize: 4, valSize: 1, ncpu: 1}
	m.store.append(mkChunk([]byte{1, 2, 3, 4}))
	m.keyFilter.SetValue("01")
	first := m.applyKeyFilter()
	m.keyFilter.SetValue("02")
	m.applyKeyFilter()
	if msg := first(); msg != nil {
		t.Fatalf("superseded search returned %#v, want nil", msg)
	}
}

func TestStorePerCPULayout(t *testing.T) {
	s := entryStore{keySize: 2, valSize: 3, ncpu: 2}
	s.append(&chunk{n: 1, keys: []byte{0, 0}, vals: []byte{1, 1, 1, 2, 2, 2}})
	s.append(&chunk{n: 2, keys: []byte{1, 0, 2, 0}, vals: []byte{3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6}})

	if !bytes.Equal(s.key(2), []byte{2, 0}) {
		t.Fatalf("key(2) = %v", s.key(2))
	}
	v := s.values(2)
	if len(v) != 2 || !bytes.Equal(v[0], []byte{5, 5, 5}) || !bytes.Equal(v[1], []byte{6, 6, 6}) {
		t.Fatalf("values(2) = %v", v)
	}
	if v := s.values(0); !bytes.Equal(v[1], []byte{2, 2, 2}) {
		t.Fatalf("values(0) = %v", v)
	}
}

func TestByteArraySlice(t *testing.T) {
	v, buf := byteArraySlice(3, 4)
	if v.Len() != 4 || len(buf) != 12 {
		t.Fatalf("len = %d/%d", v.Len(), len(buf))
	}
	v.Index(2).Index(1).SetUint(7) // element 2, byte 1 → flat offset 7
	if buf[7] != 7 {
		t.Fatalf("flat view does not alias the typed slice: %v", buf)
	}
}

func TestEntryRefreshUpdatesOnlyThatEntry(t *testing.T) {
	m := initialModel(false)
	m.view = viewDetail
	m.curMap = mapRow{Type: ebpf.Hash}
	m.loadGen = 3
	m.store = entryStore{keySize: 4, valSize: 1, ncpu: 1}
	m.store.append(mkChunk([]byte{1, 0, 0, 0}, []byte{2, 0, 0, 0})) // values 0, 1
	m.detailIdx = 1

	next, _ := m.Update(entryRefreshed{gen: 3, idx: 1, vals: [][]byte{{42}}})
	m = next.(model)
	if v := m.store.values(1)[0][0]; v != 42 {
		t.Fatalf("refreshed value = %d, want 42", v)
	}
	if v := m.store.values(0)[0][0]; v != 0 {
		t.Fatalf("other entry changed to %d", v)
	}

	next, _ = m.Update(entryRefreshed{gen: 3, idx: 1, err: ebpf.ErrKeyNotExist})
	if !next.(model).detailGone {
		t.Fatalf("deleted key not flagged")
	}

	// A result for a store that has since been reloaded must be dropped.
	next, _ = m.Update(entryRefreshed{gen: 2, idx: 1, vals: [][]byte{{9}}})
	m = next.(model)
	if v := m.store.values(1)[0][0]; v != 42 {
		t.Fatalf("stale refresh applied: %d", v)
	}
}

func TestMapRefreshRestoresCursor(t *testing.T) {
	m := initialModel(false)
	m.view = viewEntries
	m.curMap = mapRow{ID: 1, Type: ebpf.Hash}
	m.height = 40
	m.store = entryStore{keySize: 4, valSize: 1, ncpu: 1}
	m.store.append(mkChunk(make([]byte, 4), make([]byte, 4), make([]byte, 4)))
	m.entryPane.cur = 2

	next, _ := m.refresh() // the returned cmd would hit the kernel; feed chunks by hand
	m = next.(model)
	if m.store.total != 0 || m.pendingCur != 2 {
		t.Fatalf("after refresh: total=%d pendingCur=%d", m.store.total, m.pendingCur)
	}
	next, _ = m.Update(chunkLoaded{gen: m.loadGen, loader: nil, chunk: mkChunk(make([]byte, 4), make([]byte, 4), make([]byte, 4))})
	m = next.(model)
	if m.entryPane.cur != 2 {
		t.Fatalf("cursor = %d, want restored to 2", m.entryPane.cur)
	}
}

// Keep tests away from the user's real ~/.config/ebpfexplorer/formats.json.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ebpfexplorer-test")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_CONFIG_HOME", dir)
	// The default (next to the binary) would write into the test binary's
	// build directory; keep everything in the temporary config dir instead.
	useGlobalConfig = true
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func press(m model, keys ...string) model {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		next, _ := m.Update(msg)
		m = next.(model)
	}
	return m
}

func TestFormatEditorFlow(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(model)
	m.view = viewEntries
	m.curMap = mapRow{ID: 5, Name: "flows", Type: ebpf.Hash, KeySize: 8, ValueSize: 1}
	m.store = entryStore{keySize: 8, valSize: 1, ncpu: 1}
	m.store.append(mkChunk(cat(le32(7), le32(443))))

	// No format yet: hex.
	if out := m.renderEntryList(); !strings.Contains(out, "07 00 00 00") || !strings.Contains(m.status(), "[HEX: no format, press e]") {
		t.Fatalf("expected hex without a format:\n%s\n%s", out, m.status())
	}

	// Wrong size is rejected; enter never closes the editor.
	m = press(m, "e", "__u32", "enter")
	if m.fmtEdit == nil || !strings.Contains(m.fmtEdit.errs[0], "4 bytes but the map's key is 8 bytes") {
		t.Fatalf("expected size error, editor=%+v", m.fmtEdit)
	}
	// esc always leaves, saving only what is valid, and says what wasn't.
	m = press(m, "esc")
	if m.fmtEdit != nil || m.formats.get(m.curMap).key != nil || m.err == nil ||
		!strings.Contains(m.err.Error(), "not saved: key format: definition is 4 bytes") {
		t.Fatalf("esc with an invalid key: editor=%v err=%v", m.fmtEdit, m.err)
	}
	m.err = nil
	m = press(m, "e", "struct {int a; int b;}", "esc")
	if m.fmtEdit != nil {
		t.Fatalf("editor still open: %v", m.fmtEdit.errs)
	}

	if out := m.renderEntryList(); !strings.Contains(out, "a=7 b=443") {
		t.Fatalf("formatted key missing:\n%s", out)
	}
	// The value side has no format, so it stays hex.
	if strings.Contains(m.status(), "[HEX") {
		t.Fatalf("status = %q, want [FORMAT]", m.status())
	}

	// Search matches the formatted key text.
	runSearch(t, &m, "b=443")
	if m.visCount() != 1 {
		t.Fatalf("search on formatted key: %d matches", m.visCount())
	}

	// Persisted by name: a reloaded store sees it.
	s, err := loadFormats(m.formats.path)
	if err != nil || s.get(mapRow{Name: "flows"}).key == nil {
		t.Fatalf("format not persisted: %v", err)
	}
}

func TestUsageLines(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 20})
	m = next.(model)
	next, _ = m.Update(progsLoaded{rows: []progRow{
		{ID: 41, Name: "xdp_filter", Type: ebpf.XDP, MapIDs: []ebpf.MapID{12}, Attached: "xdp@eth0 (native)"},
		{ID: 42, Name: "tc_stats", Type: ebpf.SchedCLS, MapIDs: []ebpf.MapID{12, 13}},
	}})
	m = next.(model)

	// Opening a program starts a /proc scan for its holders.
	m = press(m, "enter")
	if m.view != viewMaps || m.holdersFor != "prog:41" || m.holdersDone {
		t.Fatalf("view=%v holdersFor=%s done=%v", m.view, m.holdersFor, m.holdersDone)
	}
	if v := m.View(); !strings.Contains(v, "attached: xdp@eth0 (native)") || !strings.Contains(v, "processes: finding…") {
		t.Fatalf("maps view header:\n%s", v)
	}
	next, _ = m.Update(holdersLoaded{key: "prog:41", holders: []string{"proxy-agent (pid 2211)"}})
	m = next.(model)
	if v := m.View(); !strings.Contains(v, "processes: proxy-agent (pid 2211)") {
		t.Fatalf("holders not shown:\n%s", v)
	}

	// A map lists every program using it, plus its own holders. A late
	// result for program 12 must not leak into map 12 (IDs overlap).
	m.view = viewEntries
	m.curMap = mapRow{ID: 12, Name: "flows", Type: ebpf.Hash}
	m.loadHolders()
	next, _ = m.Update(holdersLoaded{key: "prog:12", holders: []string{"stale (pid 1)"}})
	m = next.(model)
	v := m.View()
	lines := strings.Split(v, "\n")
	if len(lines) < 4 ||
		strings.TrimSpace(lines[2]) != "programs: xdp_filter (41), tc_stats (42)" ||
		strings.TrimSpace(lines[3]) != "processes: finding…" ||
		strings.Contains(v, "stale") {
		t.Fatalf("entries view header (programs and processes on separate lines):\n%s", v)
	}
}

func TestHorizontalScroll(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 90, Height: 20})
	m = next.(model)
	m.view = viewEntries
	m.curMap = mapRow{ID: 9, Name: "wide", Type: ebpf.Hash, KeySize: 32, ValueSize: 1}
	m.store = entryStore{keySize: 32, valSize: 1, ncpu: 1}
	key := make([]byte, 32)
	key[31] = 0xab // last byte: hidden until scrolled
	m.store.append(mkChunk(key))

	if out := m.renderEntryList(); strings.Contains(out, "ab") {
		t.Fatalf("last byte should be cut off at first:\n%s", out)
	}
	for range 20 {
		m = press(m, "right")
	}
	if m.view != viewEntries {
		t.Fatal("→ must scroll, not open the entry")
	}
	if out := m.renderEntryList(); !strings.Contains(out, "00 ab") {
		t.Fatalf("scrolled fully right, the last byte must show:\n%s", out)
	}
	if m.entryPane.hOff != m.overflow() {
		t.Fatalf("scroll should stop at the overflow: %d vs %d", m.entryPane.hOff, m.overflow())
	}

	for m.entryPane.hOff > 0 {
		m = press(m, "left")
	}
	if m.view != viewEntries {
		t.Fatalf("← should scroll back to 0 first: off=%d view=%v", m.entryPane.hOff, m.view)
	}
	if m = press(m, "left"); m.view != viewMaps {
		t.Fatal("← at the left edge goes back to the maps")
	}
}

// scrollFully presses → until nothing moves, returning the rendered screen.
func scrollFully(t *testing.T, m model) (model, string) {
	t.Helper()
	for range 100 {
		before := m.paneState().hOff
		m = press(m, "right")
		if m.paneState().hOff == before {
			break
		}
	}
	return m, m.View()
}

func TestHorizontalScrollEverywhere(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 20})
	m = next.(model)
	long := "cgroup/device@a-very-long-systemd-unit-name-that-does-not-fit.service"
	next, _ = m.Update(progsLoaded{rows: []progRow{
		{ID: 7, Name: "sd_devices", Type: ebpf.CGroupDevice, MapIDs: []ebpf.MapID{3}, Attached: long},
	}})
	m = next.(model)

	// Programs: the end of a cut-off Attached cell becomes visible.
	if strings.Contains(m.View(), "fit.service") {
		t.Fatal("attached label should be cut off at first")
	}
	m, v := scrollFully(t, m)
	if !strings.Contains(v, "fit.service") || m.view != viewProgs {
		t.Fatalf("programs: → should reveal the end of the cell:\n%s", v)
	}
	for m.paneState().hOff > 0 {
		m = press(m, "left")
	}

	// Maps: the header line scrolls too.
	m = press(m, "enter")
	next, _ = m.Update(holdersLoaded{key: "prog:7", holders: []string{"systemd (pid 1)", "some-other-long-process-name (pid 4242)"}})
	m = next.(model)
	if strings.Contains(m.View(), "pid 4242") {
		t.Fatal("maps header should be cut off at first")
	}
	m, v = scrollFully(t, m)
	if !strings.Contains(v, "pid 4242") {
		t.Fatalf("maps: → should reveal the end of the header line:\n%s", v)
	}
	for m.paneState().hOff > 0 {
		m = press(m, "left")
	}
	if m = press(m, "left"); m.view != viewProgs {
		t.Fatal("maps: ← at the left edge goes back")
	}

	// Detail: long lines scroll, ← at the edge goes back to the entries.
	m.view = viewEntries
	m.curMap = mapRow{ID: 3, Name: "m", Type: ebpf.Hash, KeySize: 64, ValueSize: 1}
	m.store = entryStore{keySize: 64, valSize: 1, ncpu: 1}
	key := make([]byte, 64)
	key[63] = 0xcd
	m.store.append(mkChunk(key))
	m = press(m, "enter")
	if m.view != viewDetail {
		t.Fatal("enter should open the entry")
	}
	m.detailLines = append(m.detailLines, strings.Repeat("x", 120)+"END")
	if strings.Contains(m.View(), "END") {
		t.Fatal("long detail line should be cut off at first")
	}
	m, v = scrollFully(t, m)
	if !strings.Contains(v, "END") {
		t.Fatalf("detail: → should reveal the end of long lines:\n%s", v)
	}
	for m.paneState().hOff > 0 {
		m = press(m, "left")
	}
	if m = press(m, "left"); m.view != viewEntries {
		t.Fatal("detail: ← at the left edge goes back")
	}
}

func TestPerCPUEntryTable(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 20})
	m = next.(model)
	m.view = viewEntries
	m.loadGen = 1
	m.curMap = mapRow{ID: 1305, Name: "limits", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 16}
	m.store = entryStore{keySize: 4, valSize: 16, ncpu: 3}
	m.store.append(&chunk{n: 1, keys: le32(1), vals: cat(
		le64(1), le64(10), le64(2), le64(20), le64(3), le64(30))})
	v, _ := parseCType("struct { __u64 count; __u64 bps; }")
	m.formats.compiled["limits"] = compiledFormat{value: v}

	m = press(m, "enter")
	out := m.View()
	for _, want := range []string{"key: 01 00 00 00", "CPU", "count", "bps"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	// One row per CPU plus Σ, not one text block per CPU.
	if tbl, ok := m.table(); !ok || tbl.n != 4 {
		t.Fatalf("expected a 4-row table (Σ + 3 CPUs), got ok=%v n=%d", ok, tbl.n)
	}
	if got := m.cpuTable().row(0); !slices.Equal(got, []string{"Σ", "6", "60"}) {
		t.Fatalf("Σ row = %v", got)
	}

	// r re-reads only this entry; the table shows the new values.
	if _, cmd := m.refresh(); cmd == nil {
		t.Fatal("r should start a single-entry refresh")
	}
	next, _ = m.Update(entryRefreshed{gen: 1, idx: 0, vals: [][]byte{
		cat(le64(5), le64(50)), cat(le64(5), le64(50)), cat(le64(5), le64(50))}})
	m = next.(model)
	if got := m.cpuTable().row(2); !slices.Equal(got, []string{"1", "5", "50"}) {
		t.Fatalf("cpu1 row after refresh = %v", got)
	}
}

func TestAllMapsList(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 20})
	m = next.(model)
	next, _ = m.Update(progsLoaded{rows: []progRow{{ID: 41, Name: "xdp_filter", Type: ebpf.XDP, MapIDs: []ebpf.MapID{12}}}})
	m = next.(model)
	m = press(m, "enter") // the program's maps, still loading
	stale := mapsLoaded{gen: m.mapsGen, rows: []mapRow{{ID: 12, Name: "flows"}}}

	m = press(m, "m")
	if m.view != viewMaps || !m.allMaps || !m.mapsLoading {
		t.Fatalf("m opens the list of all maps: view=%v allMaps=%v", m.view, m.allMaps)
	}
	next, _ = m.Update(stale)
	if m = next.(model); len(m.maps) != 0 {
		t.Fatal("a late listing of the program's maps must be dropped")
	}
	next, _ = m.Update(mapsLoaded{gen: m.mapsGen, rows: []mapRow{
		{ID: 12, Name: "flows", Type: ebpf.Hash, KeySize: 4, ValueSize: 8},
		{ID: 30, Name: "pp_id_2_user_id", Type: ebpf.Hash, KeySize: 4, ValueSize: 4},
	}})
	m = next.(model)
	if v := m.View(); !strings.Contains(v, "all maps") || !strings.Contains(v, "pp_id_2_user_id") || !strings.Contains(v, "2 maps") {
		t.Fatalf("all maps view:\n%s", v)
	}

	// / filters; esc clears the filter, then stays: this is a starting list.
	m = press(m, "/", "user", "enter")
	if r, ok := m.curMapRow(); len(m.visMaps) != 1 || !ok || r.ID != 30 {
		t.Fatalf("filter: %v", m.visMaps)
	}
	m = press(m, "esc")
	if len(m.visMaps) != 2 || m.view != viewMaps {
		t.Fatal("esc clears the maps filter")
	}
	m = press(m, "esc")
	if m.view != viewMaps || !m.allMaps {
		t.Fatal("esc on the all maps list stays there")
	}

	// A map opened from it goes back to it.
	m = press(m, "down", "enter")
	if m.view != viewEntries || m.curMap.ID != 30 {
		t.Fatalf("view=%v map=%d", m.view, m.curMap.ID)
	}
	if m = press(m, "esc"); m.view != viewMaps || !m.allMaps || len(m.maps) != 2 {
		t.Fatal("esc from the entries goes back to all maps")
	}

	m = press(m, "p")
	if m.view != viewProgs || m.allMaps {
		t.Fatalf("p goes back to the programs: view=%v allMaps=%v", m.view, m.allMaps)
	}
	if v := m.View(); !strings.Contains(v, "[m] all maps") {
		t.Fatalf("programs help:\n%s", v)
	}
}
