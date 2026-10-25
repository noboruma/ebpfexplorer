package internal

import (
	"bytes"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
)

// fakeTarget serves lookups from a map of key bytes to one value.
func fakeTarget(entries map[string][]byte) func(mapRow) (*linkTarget, error) {
	return func(row mapRow) (*linkTarget, error) {
		return &linkTarget{
			row: row,
			lookup: func(k []byte) ([][]byte, error) {
				if v, ok := entries[string(k)]; ok {
					return [][]byte{v}, nil
				}
				return nil, ebpf.ErrKeyNotExist
			},
			close: func() {},
		}, nil
	}
}

func TestLinkEditorFlow(t *testing.T) {
	m := initialModel(false)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 160, Height: 40})
	m = next.(model)
	m.view = viewEntries
	m.curProg = progRow{ID: 1, MapIDs: []ebpf.MapID{5, 14}}
	m.curMap = mapRow{ID: 5, Name: "lflows", Type: ebpf.Hash, KeySize: 8, ValueSize: 1}
	m.store = entryStore{keySize: 8, valSize: 1, ncpu: 1}
	m.store.append(mkChunk(cat(le32(3), le32(443)), cat(le32(9), le32(80))))
	backends := mapRow{ID: 14, Name: "backends", Type: ebpf.Hash, KeySize: 4, ValueSize: 8}
	wide := mapRow{ID: 15, Name: "wide", Type: ebpf.Hash, KeySize: 16, ValueSize: 4}

	// Links sit in the format editor, after the key and value.
	m = press(m, "e", "struct { __u32 backend_id; __u32 port; }", "down", "down")
	if m.fmtEdit == nil || m.fmtEdit.focus != focusLinks || m.fmtEdit.linkCur != 0 {
		t.Fatal("↓ from the key goes to the value, then to the first link field")
	}
	if m = press(m, "up"); m.fmtEdit.focus != 1 {
		t.Fatal("↑ from the first link field goes back to the value")
	}
	m = press(m, "down")
	next, _ = m.Update(mapsListed{rows: []mapRow{wide, backends}})
	m = next.(model)
	e := m.fmtEdit
	var paths []string
	for _, s := range e.sources {
		paths = append(paths, s.path)
	}
	if strings.Join(paths, " ") != "key key.backend_id key.port value" {
		t.Fatalf("sources = %v", paths)
	}

	// enter on a field lists every map, even those that don't fit; picking
	// one is checked.
	m = press(m, "down", "enter")
	if m.fmtEdit.picker == nil || len(m.fmtEdit.pickItems()) != 3 {
		t.Fatalf("picker should list (no link) + both maps")
	}
	if v := m.View(); !strings.Contains(v, "Link key.backend_id (4B) to") || !strings.Contains(v, "wide") {
		t.Fatalf("picker popup not shown:\n%s", v)
	}
	m = press(m, "wide", "down", "enter")
	if p := m.fmtEdit.picker; p == nil || !strings.Contains(p.err, `key.backend_id is 4B but "wide" keys are 16B`) {
		t.Fatalf("an incompatible map must be refused: %+v", p)
	}
	m = press(m, "esc", "enter", "back", "down", "enter")
	if m.fmtEdit.picker != nil || m.fmtEdit.links["key.backend_id"] != "backends" {
		t.Fatalf("links = %v", m.fmtEdit.links)
	}
	if c, _ := m.fmtEdit.checkLink(1); c != checkOK {
		t.Fatalf("link check = %v", c)
	}
	m = press(m, "esc") // saves
	if m.fmtEdit != nil {
		t.Fatal("esc should save and close")
	}
	s, err := loadFormats(m.formats.path)
	if err != nil || s.def(m.curMap).Links["key.backend_id"] != "backends" || s.def(m.curMap).Key == "" {
		t.Fatalf("links not persisted with the format: %+v %v", s.def(m.curMap), err)
	}

	// Resolve against a fake backends map; entry 9 has no backend.
	v, _ := parseCType("struct { ipv4 ip; __u16 port; }")
	m.formats.compiled["backends"] = compiledFormat{value: v}
	kf, vf := m.activeFormats()
	links := buildLinks(m.formats.def(m.curMap).Links, linkSources(m.curMap, kf, vf), []mapRow{backends, wide}, nil,
		fakeTarget(map[string][]byte{string(le32(3)): cat([]byte{10, 0, 0, 5}, le16(80), le16(0))}))
	next, _ = m.Update(linksResolved{gen: m.linkGen, links: links})
	m = next.(model)

	// The translation follows the field in the Key column itself.
	out := m.renderEntryList()
	for _, want := range []string{"Key (linked)", "backend_id=3→{ip=10.0.0.5 port=80} port=443", "backend_id=9→(not found) port=80"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Value (linked)") {
		t.Fatal("the value has no links")
	}

	// Search matches the translated values.
	runSearch(t, &m, "10.0.0.5")
	if m.visCount() != 1 || m.visAt(0) != 0 {
		t.Fatalf("search on a linked value: %d matches", m.visCount())
	}
	runSearch(t, &m, "")

	m = press(m, "enter")
	detail := strings.Join(m.detailLines, "\n")
	for _, want := range []string{"backend_id = 3→{ip=10.0.0.5 port=80}", "port = 443"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("detail missing %q:\n%s", want, detail)
		}
	}

	// Editing the format again keeps the links.
	m = press(m, "e", ";", "esc")
	if s, _ := loadFormats(m.formats.path); !strings.HasSuffix(s.def(m.curMap).Key, ";") || s.def(m.curMap).Links["key.backend_id"] != "backends" {
		t.Fatalf("saving the format dropped the links: %+v", s.def(m.curMap))
	}

	// Closing an unchanged editor writes nothing: a bundled format stays
	// bundled instead of being copied into the user's file.
	m.formats.setEmbedded(map[string]formatDef{"bundled": {Key: "__u64"}})
	m.view = viewEntries
	m.curMap = mapRow{ID: 6, Name: "bundled", Type: ebpf.Hash, KeySize: 8, ValueSize: 1}
	m = press(m, "e", "esc")
	if data, _ := os.ReadFile(m.formats.path); m.fmtEdit != nil || strings.Contains(string(data), "bundled") {
		t.Fatalf("unchanged esc saved: %s", data)
	}
}

func TestLinkKeyWidening(t *testing.T) {
	u16, _ := parseCType("__u16")
	s16, _ := parseCType("__s16")
	be, _ := parseCType("__be16")
	src := linkSource{path: "key", size: 2, t: u16}
	if !src.fits(4) || !bytes.Equal(src.lookupKey(le16(7), 4), le32(7)) {
		t.Fatalf("__u16 → 4B key: %v", src.lookupKey(le16(7), 4))
	}
	neg := linkSource{path: "key", size: 2, t: s16}
	if got := neg.lookupKey(le16(0xffff), 8); !bytes.Equal(got, le64(^uint64(0))) {
		t.Fatalf("__s16 -1 → 8B key: %v", got)
	}
	if (linkSource{size: 2, t: be}).fits(4) || (linkSource{size: 4}).fits(8) || (linkSource{size: 4, t: u16}).fits(2) {
		t.Fatal("only host-order integers widen, and never narrow")
	}
}

func TestPickMapPrefersProgram(t *testing.T) {
	all := []mapRow{{ID: 3, Name: "ids"}, {ID: 9, Name: "ids"}, {ID: 5, Name: "ids"}, {ID: 4, Name: "other"}}
	if r, _ := pickMap("ids", all, []ebpf.MapID{5}); r.ID != 5 {
		t.Fatalf("got map %d, want the program's own (5)", r.ID)
	}
	if r, _ := pickMap("ids", all, nil); r.ID != 9 {
		t.Fatalf("got map %d, want the newest (9)", r.ID)
	}
	if _, ok := pickMap("nope", all, nil); ok {
		t.Fatal("unknown name found")
	}
}
