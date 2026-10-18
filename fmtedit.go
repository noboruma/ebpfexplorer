package main

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/cilium/ebpf"
	"github.com/mattn/go-runewidth"
)

var (
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	labelStyle = lipgloss.NewStyle().Bold(true)
	panelStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1)
	popupStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("214")).Padding(0, 1)
)

// fmtEditor edits the key and value C definitions of one map, and the links
// of their fields (see links.go).
type fmtEditor struct {
	target mapRow
	inputs [2]textinput.Model // 0 = key, 1 = value
	focus  int                // 0 = key, 1 = value, focusLinks (row linkCur)
	parsed [2]*ctype
	errs   [2]string
	path   string    // where the format is saved, shown to the user
	orig   formatDef // as opened: closing unchanged writes nothing

	// Links: one row per field of the formats as typed.
	links   map[string]string // field path → linked map name
	sources []linkSource
	linkCur int
	maps    []mapRow // every loaded map; nil while listing
	mapsErr string
	prog    []ebpf.MapID // maps of the current program, preferred on name clashes
	picker  *mapPicker   // open map list (enter on a link), if any
}

const focusLinks = 2

func newFmtEditor(mp mapRow, d formatDef) *fmtEditor {
	e := &fmtEditor{target: mp, links: maps.Clone(d.Links), orig: d}
	if e.links == nil {
		e.links = map[string]string{}
	}
	for i, v := range []string{d.Key, d.Value} {
		in := textinput.New()
		in.Prompt = ""
		in.CharLimit = 4096
		in.Placeholder = "empty = show as hex, e.g. struct { __u32 ip; __u16 port; }"
		in.SetValue(v)
		e.inputs[i] = in
	}
	e.inputs[0].Focus()
	e.validate()
	return e
}

func (e *fmtEditor) sizes() [2]int {
	return [2]int{int(e.target.KeySize), int(e.target.ValueSize)}
}

// validate parses both inputs and checks them against the map's sizes, then
// lists the fields they define for linking.
func (e *fmtEditor) validate() {
	for i := range e.inputs {
		e.parsed[i], e.errs[i] = nil, ""
		t, err := parseOptional(e.inputs[i].Value())
		switch {
		case err != nil:
			e.errs[i] = err.Error()
		case t != nil && t.size != e.sizes()[i]:
			e.errs[i] = fmt.Sprintf("definition is %d bytes but the map's %s is %d bytes",
				t.size, []string{"key", "value"}[i], e.sizes()[i])
		default:
			e.parsed[i] = t
		}
	}
	e.sources = linkSources(e.target, e.parsed[0], e.parsed[1])
	// Links to fields not (or no longer) in the format stay listed so they
	// can be removed, or come back with the format.
	for _, path := range staleLinks(e.links, e.sources) {
		e.sources = append(e.sources, linkSource{path: path})
	}
	e.linkCur = max(0, min(e.linkCur, len(e.sources)-1))
}

func (e *fmtEditor) setMaps(rows []mapRow, err error) {
	e.maps, e.mapsErr = rows, ""
	if e.maps == nil {
		e.maps = []mapRow{}
	}
	if err != nil {
		e.mapsErr = err.Error()
	}
}

type linkCheck int

const (
	checkNone linkCheck = iota // not linked
	checkOK
	checkWarn // can't be verified now; saved anyway
	checkErr  // blocks saving
)

// checkLink validates the map linked to source i.
func (e *fmtEditor) checkLink(i int) (linkCheck, string) {
	s := e.sources[i]
	name := e.links[s.path]
	switch {
	case name == "":
		return checkNone, "not linked"
	case e.maps == nil:
		return checkWarn, "listing maps…"
	}
	row, ok := pickMap(name, e.maps, e.prog)
	switch {
	case s.size == 0:
		return checkWarn, s.path + " is not in the format"
	case !ok:
		return checkWarn, fmt.Sprintf("no map named %q is loaded right now", name)
	case !s.fits(int(row.KeySize)):
		return checkErr, sizeMismatch(s, row).Error()
	}
	return checkOK, fmt.Sprintf("map %d %q: key %dB, value %dB", row.ID, row.Name, row.KeySize, row.ValueSize)
}

func (e *fmtEditor) setFocus(f int) {
	if e.focus < focusLinks {
		e.inputs[e.focus].Blur()
	}
	e.focus = f
	if f < focusLinks {
		e.inputs[f].Focus()
	}
}

// The editor is one list, moved through with ↑/↓: Key, Value, then each
// linkable field. enter picks the map of a field; esc saves and leaves.
func (m model) updateFmtEditor(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := m.fmtEdit
	if e.picker != nil {
		e.updatePicker(msg)
		return m, nil
	}
	switch msg.String() {
	case "esc":
		return m.closeFormat()
	case "up":
		e.move(-1)
		return m, textinput.Blink
	case "down":
		e.move(1)
		return m, textinput.Blink
	case "enter":
		if e.focus == focusLinks {
			e.openPicker()
		}
		return m, nil
	}
	if e.focus == focusLinks {
		switch msg.String() {
		case "backspace", "delete":
			delete(e.links, e.sources[e.linkCur].path)
			e.validate()
		}
		return m, nil
	}
	var cmd tea.Cmd
	e.inputs[e.focus], cmd = e.inputs[e.focus].Update(msg)
	e.validate()
	return m, cmd
}

// move goes up (-1) or down (+1) the list Key, Value, link fields.
func (e *fmtEditor) move(d int) {
	row := e.focus
	if e.focus == focusLinks {
		row += e.linkCur
	}
	row = max(0, min(row+d, focusLinks+len(e.sources)-1))
	e.setFocus(min(row, focusLinks))
	if row >= focusLinks {
		e.linkCur = row - focusLinks
	}
}

// closeFormat saves what is valid and leaves. A definition with an error
// keeps the one saved before, and a link that doesn't fit is dropped; the
// status line says so.
func (m model) closeFormat() (tea.Model, tea.Cmd) {
	e := m.fmtEdit
	m.fmtEdit = nil
	var notSaved []error
	def := formatDef{Key: e.orig.Key, Value: e.orig.Value}
	for i, side := range []*string{&def.Key, &def.Value} {
		if e.errs[i] != "" {
			notSaved = append(notSaved, fmt.Errorf("%s format: %s", []string{"key", "value"}[i], e.errs[i]))
			continue
		}
		*side = strings.TrimSpace(e.inputs[i].Value())
	}
	links := maps.Clone(e.links)
	for i, s := range e.sources {
		if c, msg := e.checkLink(i); c == checkErr {
			delete(links, s.path)
			notSaved = append(notSaved, fmt.Errorf("link %s: %s", s.path, msg))
		}
	}
	if len(links) > 0 {
		def.Links = links
	}
	if def.Key == strings.TrimSpace(e.orig.Key) && def.Value == strings.TrimSpace(e.orig.Value) && maps.Equal(def.Links, e.orig.Links) {
		// Unchanged: don't copy a bundled format into the user's file.
		m.err = notSavedErr(notSaved)
		return m, nil
	}
	err := m.formats.set(e.target, def, compileDef(def))
	cmd := m.formatsChanged()
	if err != nil {
		notSaved = append([]error{fmt.Errorf("saving format: %w", err)}, notSaved...)
	}
	m.err = notSavedErr(notSaved)
	return m, cmd
}

func notSavedErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return errors.New("not saved: " + strings.Join(msgs, "; "))
}

// --- map picker ---

// mapPicker is the popup listing every loaded map, to link the field under
// the cursor to one of them.
type mapPicker struct {
	filter textinput.Model
	cur    int
	err    string
}

type pickItem struct {
	row  mapRow
	none bool // the "no link" item
}

func (e *fmtEditor) openPicker() {
	f := textinput.New()
	f.Prompt = "/"
	f.Placeholder = "filter by name, id or type"
	f.Focus()
	e.picker = &mapPicker{filter: f}
	// Start on the map already linked.
	name := e.links[e.sources[e.linkCur].path]
	for i, it := range e.pickItems() {
		if !it.none && it.row.Name == name {
			e.picker.cur = i
			break
		}
	}
}

// pickItems lists the maps matching the filter: "no link" first, then the
// program's own maps, then every other map, by name.
func (e *fmtEditor) pickItems() []pickItem {
	q := strings.ToLower(strings.TrimSpace(e.picker.filter.Value()))
	rows := slices.Clone(e.maps)
	own := func(r mapRow) bool { return slices.Contains(e.prog, r.ID) }
	slices.SortStableFunc(rows, func(a, b mapRow) int {
		if own(a) != own(b) {
			if own(a) {
				return -1
			}
			return 1
		}
		return cmp.Or(strings.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	items := []pickItem{{none: true}}
	for _, r := range rows {
		if r.Name == "" { // links are saved by name
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%s %d %s", r.Name, r.ID, r.Type)), q) {
			continue
		}
		items = append(items, pickItem{row: r})
	}
	return items
}

func (e *fmtEditor) updatePicker(msg tea.KeyMsg) {
	p := e.picker
	items := e.pickItems()
	src := e.sources[e.linkCur]
	switch msg.String() {
	case "esc":
		e.picker = nil
		return
	case "up", "down", "pgup", "pgdown", "home", "end":
		pp := pane{cur: p.cur}
		pp.move(msg.String(), len(items), 10)
		p.cur, p.err = pp.cur, ""
		return
	case "enter":
		it := items[p.cur]
		switch {
		case it.none:
			delete(e.links, src.path)
		case src.size > 0 && !src.fits(int(it.row.KeySize)):
			p.err = sizeMismatch(src, it.row).Error()
			return
		default:
			e.links[src.path] = it.row.Name
		}
		e.picker = nil
		e.validate()
		return
	}
	p.filter, _ = p.filter.Update(msg)
	p.cur, p.err = 0, ""
}

func (e *fmtEditor) pickerView(width, height int) string {
	p := e.picker
	src := e.sources[e.linkCur]
	items := e.pickItems()
	var b strings.Builder
	size := ""
	if src.size > 0 {
		size = fmt.Sprintf(" (%dB)", src.size)
	}
	b.WriteString(labelStyle.Render("Link "+src.path+size+" to") + "\n")
	p.filter.Width = width - 6
	b.WriteString(p.filter.View() + "\n")

	rows := max(3, height-6)
	first := max(0, min(p.cur-rows/2, len(items)-rows))
	for i := first; i < min(len(items), first+rows); i++ {
		it := items[i]
		var line string
		fits := true
		if it.none {
			line = "(no link)"
		} else {
			r := it.row
			tag := ""
			if slices.Contains(e.prog, r.ID) {
				tag = " •"
			}
			line = fmt.Sprintf("%-16s %6d  %-12s key %3dB  value %4dB%s", r.Name, r.ID, r.Type, r.KeySize, r.ValueSize, tag)
			fits = src.size == 0 || src.fits(int(r.KeySize))
		}
		line = runewidth.FillRight(runewidth.Truncate(line, width-6, "…"), width-6)
		switch {
		case i == p.cur:
			line = selectedStyle.Render(line)
		case !fits:
			line = crumbStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	switch {
	case p.err != "":
		b.WriteString(errStyle.Render("✗ " + p.err))
	case e.maps == nil:
		b.WriteString(crumbStyle.Render("listing maps…"))
	case e.mapsErr != "":
		b.WriteString(errStyle.Render("listing maps: " + e.mapsErr))
	default:
		b.WriteString(crumbStyle.Render(fmt.Sprintf("%d maps • used by this program • greyed: key size doesn't fit", len(items)-1)))
	}
	return popupStyle.Width(width - 2).Render(b.String())
}

// overlay draws box over base with its top-left corner at column x, row y.
func overlay(base, box string, x, y int) string {
	lines := strings.Split(base, "\n")
	for i, bl := range strings.Split(box, "\n") {
		r := y + i
		for r >= len(lines) {
			lines = append(lines, "")
		}
		left := ansi.Truncate(lines[r], x, "")
		if w := ansi.StringWidth(left); w < x {
			left += strings.Repeat(" ", x-w)
		}
		lines[r] = left + bl + ansi.TruncateLeft(lines[r], x+ansi.StringWidth(bl), "")
	}
	return strings.Join(lines, "\n")
}

// --- view ---

func (e *fmtEditor) view(width, height int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s map %d %q (key %dB, value %dB)\n",
		labelStyle.Render("Format for"), e.target.ID, e.target.Name, e.target.KeySize, e.target.ValueSize)
	where := "saved by map name, so it applies again after the program is reloaded"
	if e.path != "" {
		where = "saved by map name in " + e.path
	}
	b.WriteString(crumbStyle.Render(where) + "\n\n")

	inner := max(20, width-6)
	for i, label := range []string{"Key", "Value"} {
		e.inputs[i].Width = inner - 2
		b.WriteString(e.marker(i) + labelStyle.Render(label) + "\n  " + e.inputs[i].View() + "\n  ")
		switch {
		case e.errs[i] != "":
			b.WriteString(errStyle.Render("✗ " + e.errs[i]))
		case e.parsed[i] != nil:
			b.WriteString(okStyle.Render(fmt.Sprintf("✓ %d bytes", e.parsed[i].size)))
		default:
			b.WriteString(crumbStyle.Render("shown as hex"))
		}
		b.WriteString("\n\n")
	}
	e.linksView(&b, inner, height)
	b.WriteString(crumbStyle.Render(
		"types:  char short int long unsigned…  __u8…__u64 __s8…__s64 uint8_t…  __be16/32/64  bool float double\n" +
			"extras: ipv4 ipv6 mac, x8…x64 (hex); arrays a[N], nested struct/union, pointers\n" +
			"attrs:  __attribute__((packed)), __attribute__((aligned(N)))"))
	out := panelStyle.Width(inner + 2).Render(b.String())
	if e.picker != nil {
		out = overlay(out, e.pickerView(min(width-4, 90), height-4), 3, 2)
	}
	return out
}

func (e *fmtEditor) marker(focus int) string {
	if e.focus == focus {
		return "▸ "
	}
	return "  "
}

// linksView lists every field of the formats with the map it is linked to.
func (e *fmtEditor) linksView(b *strings.Builder, inner, height int) {
	b.WriteString(e.marker(focusLinks) + labelStyle.Render("Links") + "  " +
		crumbStyle.Render("a linked field is looked up as a key in that map and the value found there is shown") + "\n")
	pathW := 10
	for _, s := range e.sources {
		pathW = max(pathW, len(s.path))
	}
	pathW = min(pathW, inner/2)
	fmt.Fprintf(b, "    %s\n", crumbStyle.Render(fmt.Sprintf("%-*s  %5s  %s", pathW, "Field", "Size", "Linked map")))

	// Fields beyond the panel's height scroll with the cursor.
	rows := max(3, height-24)
	first := max(0, min(e.linkCur-rows/2, len(e.sources)-rows))
	for i := first; i < min(len(e.sources), first+rows); i++ {
		s := e.sources[i]
		marker := "    "
		if e.focus == focusLinks && i == e.linkCur {
			marker = "  ▸ "
		}
		size := "?"
		if s.size > 0 {
			size = fmt.Sprintf("%dB", s.size)
		}
		name := e.links[s.path]
		switch c, _ := e.checkLink(i); c {
		case checkOK:
			name = okStyle.Render(name + " ✓")
		case checkErr:
			name = errStyle.Render(name + " ✗")
		case checkWarn:
			name = statusStyle.Render(name + " ?")
		}
		fmt.Fprintf(b, "%s%-*s  %5s  %s\n", marker, pathW, runewidth.Truncate(s.path, pathW, "…"), size, name)
	}
	if len(e.sources) > rows {
		b.WriteString(crumbStyle.Render(fmt.Sprintf("    %d fields, ↑/↓ for more", len(e.sources))) + "\n")
	}
	if e.focus == focusLinks {
		b.WriteString("  ")
		switch c, msg := e.checkLink(e.linkCur); c {
		case checkErr:
			b.WriteString(errStyle.Render("✗ " + msg))
		case checkWarn:
			b.WriteString(statusStyle.Render("? " + msg))
		case checkOK:
			b.WriteString(okStyle.Render("✓ " + msg))
		default:
			b.WriteString(crumbStyle.Render("not linked: press enter to pick a map"))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

// help is the footer while the editor is open.
func (e *fmtEditor) help() [][2]string {
	switch {
	case e.picker != nil:
		return [][2]string{{"↑/↓", "move"}, {"type", "filter"}, {"enter", "link"}, {"esc", "close"}}
	case e.focus == focusLinks:
		return [][2]string{{"↑/↓", "move"}, {"enter", "pick map"}, {"backspace", "unlink"}, {"esc", "save & back"}}
	}
	return [][2]string{{"↑/↓", "move"}, {"esc", "save & back"}}
}
