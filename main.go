// ebpfexplorer is an interactive browser for the BPF programs, maps and map
// entries currently loaded in the kernel.
//
//	programs ──enter──▶ maps used by program ──enter──▶ map entries ──enter──▶ entry detail
//	all maps ──enter──────────────────────────────────▶ map entries ──enter──▶ entry detail
//
// [p] and [m] switch between the two starting lists.
//
// Everything loads in the background: map entries stream in chunks of 1000
// and the UI stays usable (and searchable) while they arrive.
//
// Needs CAP_SYS_ADMIN / CAP_BPF (run with sudo).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cilium/ebpf"
)

type view int

const (
	viewProgs view = iota
	viewMaps
	viewEntries
	viewDetail
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	crumbStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	helpKeyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	statusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	headerStyle   = lipgloss.NewStyle().Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("240")).BorderBottom(true)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57"))
)

type model struct {
	view          view
	width, height int

	// allMaps: the maps list is every map loaded in the kernel (opened
	// with "m"), not the maps of curProg.
	allMaps   bool
	filter    textinput.Model // program filter
	mapFilter textinput.Model // maps filter
	keyFilter textinput.Model // entry key search
	editing   bool

	progsLoading bool
	progs        []progRow
	visProgs     []progRow
	progPane     pane
	progCols     []column

	curProg     progRow
	mapsLoading bool
	maps        []mapRow
	visMaps     []int // indexes into maps matching mapFilter
	mapPane     pane
	mapsGen     int // invalidates in-flight map listings
	mapCols     []column

	// Entries of curMap. The store only ever grows while loading; loadGen
	// invalidates in-flight chunk reads when the user leaves or refreshes.
	curMap    mapRow
	store     entryStore
	loading   bool
	loadErr   error
	loadGen   int
	entryPane pane // cur is a position in the visible list
	// pendingCur is the cursor to restore once a reload has streamed in
	// enough rows to reach it again; -1 when there is nothing to restore.
	pendingCur  int
	entryCol    []column // hex
	entryColFmt []column // with a format

	// Key search. With an empty query every entry is visible and visible is
	// unused. Otherwise visible holds matches among chunks[:filteredUpTo];
	// a full rescan runs in the background (searching) whenever the query
	// changes, and newly loaded chunks are filtered as they arrive.
	query        keyQuery
	visible      []int32
	filteredUpTo int
	searching    bool
	searchGen    *atomic.Int64

	detailLines []string
	detailPane  pane
	detailIdx   int  // store index of the entry shown in the detail view
	detailGone  bool // the key was deleted from the map since it was read
	entryReload bool // single-entry refresh in flight

	refreshedAt time.Time // when the current view was last refreshed by "r"
	err         error

	// Key/value formatting: a side with a C struct definition is shown
	// formatted, otherwise as hex. fmtEdit is the open editor (e), if any.
	formats *formatStore
	fmtEdit *fmtEditor

	// code is the open code view ([d]) of a program, if any.
	code *codeView

	// Links of curMap (see links.go); linkGen invalidates in-flight
	// resolutions.
	links   []*mapLink
	linkGen int

	// Processes holding the current program (maps view) or map (entries
	// view) open; nil while the /proc scan is running.
	holders     []string
	holdersFor  string // "prog:<id>" or "map:<id>": IDs of the two overlap
	holdersDone bool
}

func initialModel(allMaps bool) model {
	fi := textinput.New()
	fi.Prompt = "/"
	fi.Placeholder = "filter by name/type/id"
	mf := textinput.New()
	mf.Prompt = "/"
	mf.Placeholder = "filter by name/type/id"
	kf := textinput.New()
	kf.Prompt = "/"
	kf.Placeholder = "search key: hex (0a000001 / 0a 00 00 01), decimal or IP"
	m := model{
		filter:       fi,
		mapFilter:    mf,
		keyFilter:    kf,
		progsLoading: true,
		searchGen:    new(atomic.Int64),
		pendingCur:   -1,
	}
	path, err := formatsPath()
	if err == nil {
		m.formats, err = loadFormats(path)
	} else {
		m.formats, _ = loadFormats("") // usable in memory; saving reports the error
	}
	if err != nil {
		m.err = fmt.Errorf("loading formats: %w", err)
	}
	if defs, err := readEmbeddedFormats("/proc/self/exe"); err != nil {
		m.err = errors.Join(m.err, err)
	} else {
		m.formats.setEmbedded(defs)
	}
	// Data can load before the first WindowSizeMsg: lay out for a default
	// size up front.
	m.width, m.height = 80, 24
	m.resize()
	m.width = 0 // View shows "loading…" until the real size arrives
	if allMaps {
		m.showAllMaps()
	}
	return m
}

// --- async loading ---

type progsLoaded struct {
	rows []progRow
	err  error
}
type mapsLoaded struct {
	gen  int
	rows []mapRow
	err  error
}
type mapCounted struct {
	id  ebpf.MapID
	n   int
	err error
}
type chunkLoaded struct {
	gen    int
	loader *entryLoader
	chunk  *chunk
	err    error
}
type entryRefreshed struct {
	gen  int // loadGen at request time: the store must still be the same
	idx  int
	vals [][]byte
	err  error
}
type holdersLoaded struct {
	key     string
	holders []string
}
type searchDone struct {
	gen  int64
	idx  []int32
	upTo int
}

func loadProgsCmd() tea.Msg {
	rows, err := listPrograms()
	return progsLoaded{rows, err}
}

// loadMapsCmd loads the maps list: curProg's maps, or every map.
func (m *model) loadMapsCmd() tea.Cmd {
	m.mapsGen++
	m.mapsLoading = true
	return m.listMapsCmd()
}

// listMapsCmd lists the maps for the current mapsGen.
func (m model) listMapsCmd() tea.Cmd {
	gen, all, ids := m.mapsGen, m.allMaps, m.curProg.MapIDs
	return func() tea.Msg {
		if all {
			rows, err := listAllMaps()
			return mapsLoaded{gen, rows, err}
		}
		return mapsLoaded{gen, loadMaps(ids), nil}
	}
}

func countMapsCmd(rows []mapRow) tea.Cmd {
	var cmds []tea.Cmd
	for _, r := range rows {
		if r.Err != nil {
			continue
		}
		id := r.ID
		cmds = append(cmds, func() tea.Msg {
			n, err := countEntries(id)
			return mapCounted{id, n, err}
		})
	}
	return tea.Batch(cmds...)
}

// readChunkCmd reads one chunk; the first call (loader == nil) opens the map.
func readChunkCmd(id ebpf.MapID, l *entryLoader, gen int) tea.Cmd {
	return func() tea.Msg {
		if l == nil {
			var err error
			if l, err = openLoader(id); err != nil {
				return chunkLoaded{gen: gen, err: err}
			}
		}
		c, err := l.next()
		return chunkLoaded{gen, l, c, err}
	}
}

func refreshEntryCmd(id ebpf.MapID, key []byte, idx, gen int) tea.Cmd {
	return func() tea.Msg {
		vals, err := lookupEntry(id, key)
		return entryRefreshed{gen, idx, vals, err}
	}
}

// loadHolders starts the /proc scan for the processes holding the current
// program (maps view) or map (entries view) open.
func (m *model) loadHolders() tea.Cmd {
	var key string
	var scan func() []string
	switch m.view {
	case viewMaps:
		if m.allMaps {
			return nil
		}
		progID := m.curProg.ID
		key, scan = fmt.Sprintf("prog:%d", progID), func() []string { return programHolders(progID) }
	case viewEntries:
		mapID := m.curMap.ID
		key, scan = fmt.Sprintf("map:%d", mapID), func() []string { return mapHolders(mapID) }
	default:
		return nil
	}
	m.holders, m.holdersFor, m.holdersDone = nil, key, false
	return func() tea.Msg { return holdersLoaded{key, scan()} }
}

func searchCmd(s entryStore, q keyQuery, gen *atomic.Int64, want int64) tea.Cmd {
	return func() tea.Msg {
		idx, ok := filterChunks(s, 0, q, gen, want)
		if !ok {
			return nil // superseded by a newer search
		}
		return searchDone{want, idx, len(s.chunks)}
	}
}

func (m model) Init() tea.Cmd {
	if m.allMaps {
		// The programs are still loaded: they tell which programs use a map.
		return tea.Batch(loadProgsCmd, m.listMapsCmd())
	}
	return loadProgsCmd
}

// --- update ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil

	case progsLoaded:
		m.progsLoading = false
		m.progs, m.err = msg.rows, msg.err
		m.applyProgFilter()
		return m, nil

	case mapsLoaded:
		if msg.gen != m.mapsGen {
			return m, nil
		}
		m.mapsLoading = false
		m.maps = msg.rows
		if msg.err != nil {
			m.err = msg.err
		}
		m.applyMapFilter() // keeps the cursor on refresh
		return m, countMapsCmd(m.maps)

	case entryRefreshed:
		if msg.gen != m.loadGen {
			return m, nil
		}
		m.entryReload = false
		switch {
		case errors.Is(msg.err, ebpf.ErrKeyNotExist):
			m.detailGone = true
		case msg.err != nil:
			m.err = msg.err
		default:
			m.detailGone = false
			m.store.setValues(msg.idx, msg.vals)
		}
		if m.view == viewDetail && m.detailIdx == msg.idx {
			m.setDetail(m.renderEntry(msg.idx))
		}
		return m, nil

	case mapCounted:
		// Counts arrive asynchronously; ignore ones for maps no longer listed.
		for i := range m.maps {
			if m.maps[i].ID == msg.id {
				m.maps[i].Count, m.maps[i].CountErr = msg.n, msg.err
			}
		}
		if msg.id == m.curMap.ID && msg.err == nil {
			m.curMap.Count = msg.n
		}
		return m, nil

	case chunkLoaded:
		return m.onChunk(msg)

	case holdersLoaded:
		if msg.key == m.holdersFor {
			m.holders, m.holdersDone = msg.holders, true
		}
		return m, nil

	case linksResolved:
		return m.onLinksResolved(msg)

	case mapsListed:
		if m.fmtEdit != nil {
			m.fmtEdit.setMaps(msg.rows, msg.err)
		}
		return m, nil

	case codeLoaded:
		if m.code != nil && m.code.prog.ID == msg.id {
			c := m.code
			c.loading, c.rows, c.info, c.err = false, msg.rows, msg.info, msg.err
			c.pane.clamp(len(c.rows), m.codeRows())
		}
		return m, nil

	case searchDone:
		if msg.gen != m.searchGen.Load() {
			return m, nil
		}
		m.visible, m.filteredUpTo, m.searching = msg.idx, msg.upTo, false
		m.catchUpFilter()
		m.restoreCursor()
		m.clampEntryCursor()
		return m, nil

	case tea.KeyMsg:
		if m.fmtEdit != nil {
			return m.updateFmtEditor(msg)
		}
		if m.code != nil {
			return m.updateCode(msg.String())
		}
		if m.editing {
			return m.updateFilter(msg)
		}
		return m.handleKey(msg.String())
	}
	return m, nil
}

// handleKey implements the navigation shared by every screen.
func (m model) handleKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "right", "l":
		m.hscroll(hStep)
		return m, nil
	case "left", "h":
		// Scroll back first; at the left edge, go back a level.
		if m.curPane().hOff > 0 {
			m.hscroll(-hStep)
			return m, nil
		}
		return m.back()
	case "esc", "backspace":
		return m.back()
	case "enter":
		return m.drillDown()
	case "r":
		return m.refresh()
	case "e":
		if mp, ok := m.formatTarget(); ok {
			m.fmtEdit = newFmtEditor(mp, m.formats.def(mp))
			m.fmtEdit.path = m.formats.path
			m.fmtEdit.prog = m.curProg.MapIDs
			// Every loaded map, to check and pick link targets.
			return m, tea.Batch(textinput.Blink, listMapsCmd)
		}
	case "p":
		m.leaveToRoot()
		m.view, m.allMaps = viewProgs, false
		m.progsLoading = true
		return m, loadProgsCmd
	case "m":
		m.leaveToRoot()
		return m, m.showAllMaps()
	case "d":
		switch {
		case m.view == viewProgs && m.progPane.cur < len(m.visProgs):
			return m.openCode(m.visProgs[m.progPane.cur])
		case m.view == viewMaps && !m.allMaps:
			return m.openCode(m.curProg)
		}
	case "/":
		if f := m.activeFilter(); f != nil {
			m.editing = true
			f.Focus()
			return m, textinput.Blink
		}
	}

	p := m.curPane()
	if t, ok := m.table(); ok {
		p.move(key, t.n, m.listRows())
	} else if m.view == viewDetail {
		p.scrollText(key, len(m.detailLines), m.detailRows())
	}
	return m, nil
}

func (m model) onChunk(msg chunkLoaded) (tea.Model, tea.Cmd) {
	if msg.gen != m.loadGen {
		// The user left this map or refreshed: stop streaming.
		if msg.loader != nil {
			msg.loader.Close()
		}
		return m, nil
	}
	l := msg.loader
	if l != nil && len(m.store.chunks) == 0 {
		m.store.keySize, m.store.valSize, m.store.ncpu = l.keySize, l.valSize, l.ncpu
	}
	if msg.chunk != nil && msg.chunk.n > 0 {
		m.store.append(msg.chunk)
		if !m.query.empty() && !m.searching {
			m.catchUpFilter()
		}
		m.restoreCursor()
	}
	if msg.err != nil || l == nil || l.done {
		if l != nil {
			l.Close()
		}
		m.loading = false
		m.loadErr = msg.err
		if !m.searching {
			// The map shrank below the old cursor: settle for the last row.
			m.pendingCur = -1
			m.clampEntryCursor()
		}
		if msg.err == nil {
			// A full read is a fresher count than the one from the maps view.
			for i := range m.maps {
				if m.maps[i].ID == m.curMap.ID {
					m.maps[i].Count, m.maps[i].CountErr = m.store.total, nil
				}
			}
		}
		return m, nil
	}
	return m, readChunkCmd(m.curMap.ID, l, m.loadGen)
}

// leaveToRoot stops what the current view loads before jumping to one of
// the two starting lists.
func (m *model) leaveToRoot() {
	if m.view >= viewEntries {
		m.stopEntries()
	}
	m.err = nil
	m.refreshedAt = time.Time{}
	m.holders, m.holdersFor, m.holdersDone = nil, "", false
}

// showAllMaps opens the list of every map loaded in the kernel.
func (m *model) showAllMaps() tea.Cmd {
	m.view, m.allMaps = viewMaps, true
	m.curProg = progRow{}
	m.maps, m.visMaps, m.mapPane = nil, nil, pane{}
	m.mapFilter.SetValue("")
	return m.loadMapsCmd()
}

// atRoot reports whether the current view is a starting list.
func (m model) atRoot() bool {
	return m.view == viewProgs || m.view == viewMaps && m.allMaps
}

func (m model) back() (tea.Model, tea.Cmd) {
	// Clear an active search before leaving the view.
	switch {
	case m.view == viewMaps && m.mapFilter.Value() != "":
		m.mapFilter.SetValue("")
		m.applyMapFilter()
		return m, nil
	case m.atRoot():
		if m.filter.Value() != "" {
			m.filter.SetValue("")
			m.applyProgFilter()
		}
		return m, nil
	case m.view == viewEntries && m.keyFilter.Value() != "":
		m.keyFilter.SetValue("")
		return m, m.applyKeyFilter()
	case m.view == viewEntries:
		m.stopEntries()
	}
	m.view--
	if m.view == viewMaps && m.allMaps {
		// The maps were not opened from a program.
		m.err, m.refreshedAt = nil, time.Time{}
		return m, nil
	}
	m.err = nil
	m.refreshedAt = time.Time{}
	if m.view == viewMaps {
		return m, m.loadHolders()
	}
	return m, nil
}

// refresh reloads only what the current view shows: the program list, the
// program's maps (metadata and counts), one map's entries, or one entry.
func (m model) refresh() (tea.Model, tea.Cmd) {
	m.err = nil
	m.refreshedAt = time.Now()
	switch m.view {
	case viewProgs:
		m.progsLoading = true
		return m, loadProgsCmd
	case viewMaps:
		return m, tea.Batch(m.loadMapsCmd(), m.loadHolders())
	case viewEntries:
		p := m.entryPane
		cmd := m.startEntries()
		m.pendingCur, m.entryPane.off, m.entryPane.hOff = p.cur, p.off, p.hOff
		return m, tea.Batch(cmd, m.loadHolders())
	case viewDetail:
		m.entryReload = true
		m.clearLinkCaches()
		key := slices.Clone(m.store.key(m.detailIdx))
		return m, refreshEntryCmd(m.curMap.ID, key, m.detailIdx, m.loadGen)
	}
	return m, nil
}

// restoreCursor puts the cursor back where it was before a reload once
// enough rows are visible again.
func (m *model) restoreCursor() {
	if m.pendingCur < 0 || m.searching || m.visCount() <= m.pendingCur {
		return
	}
	m.entryPane.cur, m.pendingCur = m.pendingCur, -1
	m.clampEntryCursor()
}

// --- program/key filters ---

// activeFilter returns the search input of the current view, if it has one.
func (m *model) activeFilter() *textinput.Model {
	switch m.view {
	case viewProgs:
		return &m.filter
	case viewMaps:
		return &m.mapFilter
	case viewEntries:
		return &m.keyFilter
	}
	return nil
}

func (m model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := m.activeFilter()
	var cmd tea.Cmd
	switch msg.String() {
	case "enter", "esc":
		m.editing = false
		f.Blur()
		if msg.String() == "esc" {
			f.SetValue("")
		}
	default:
		*f, cmd = f.Update(msg)
	}
	switch m.view {
	case viewProgs:
		m.applyProgFilter()
		return m, cmd
	case viewMaps:
		m.applyMapFilter()
		return m, cmd
	}
	if newKeyQuery(m.keyFilter.Value()).raw == m.query.raw {
		return m, cmd
	}
	return m, tea.Batch(cmd, m.applyKeyFilter())
}

func (m *model) applyProgFilter() {
	q := strings.ToLower(m.filter.Value())
	m.visProgs = m.visProgs[:0]
	for _, p := range m.progs {
		if q != "" {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s", p.ID, p.Name, p.Type, p.Attached))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		m.visProgs = append(m.visProgs, p)
	}
	m.progPane.clamp(len(m.visProgs), m.listRows())
}

func (m *model) applyMapFilter() {
	q := strings.ToLower(m.mapFilter.Value())
	m.visMaps = m.visMaps[:0]
	for i, r := range m.maps {
		if q != "" {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s", r.ID, r.Name, r.Type))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		m.visMaps = append(m.visMaps, i)
	}
	m.mapPane.clamp(len(m.visMaps), m.listRows())
}

// curMapRow is the map under the cursor of the maps list.
func (m model) curMapRow() (mapRow, bool) {
	i := m.mapPane.cur
	if i < 0 || i >= len(m.visMaps) {
		return mapRow{}, false
	}
	return m.maps[m.visMaps[i]], true
}

// applyKeyFilter starts a background rescan for the current key query.
func (m *model) applyKeyFilter() tea.Cmd {
	m.query = newKeyQuery(m.keyFilter.Value())
	m.query.format, _ = m.activeFormats() // also match the formatted key
	m.query.links = m.links               // and what its linked fields translate to
	gen := m.searchGen.Add(1)             // also cancels any running scan
	m.entryPane.cur, m.entryPane.off = 0, 0
	if m.query.empty() {
		m.visible, m.filteredUpTo, m.searching = nil, 0, false
		return nil
	}
	m.searching = true
	return searchCmd(m.store, m.query, m.searchGen, gen)
}

// catchUpFilter filters chunks that arrived after the last scan. It runs on
// the UI goroutine, which is fine: it only ever sees a few new chunks.
func (m *model) catchUpFilter() {
	idx, _ := filterChunks(m.store, m.filteredUpTo, m.query, nil, 0)
	m.visible = append(m.visible, idx...)
	m.filteredUpTo = len(m.store.chunks)
}

// --- entries ---

func (m *model) startEntries() tea.Cmd {
	m.loadGen++
	m.store = entryStore{}
	m.loading, m.loadErr = true, nil
	m.entryPane, m.pendingCur = pane{}, -1
	m.visible, m.filteredUpTo = nil, 0
	return tea.Batch(readChunkCmd(m.curMap.ID, nil, m.loadGen), m.applyKeyFilter(), m.resolveLinks())
}

// stopEntries makes in-flight chunk reads close their loader on arrival and
// drops the data so a large map doesn't stay in memory.
func (m *model) stopEntries() {
	m.loadGen++
	m.searchGen.Add(1)
	m.loading, m.searching = false, false
	m.store = entryStore{}
	m.visible = nil
	m.dropLinks()
}

func (m *model) visCount() int {
	if m.query.empty() {
		return m.store.total
	}
	return len(m.visible)
}

func (m *model) visAt(r int) int {
	if m.query.empty() {
		return r
	}
	return int(m.visible[r])
}

func (m *model) clampEntryCursor() {
	m.entryPane.clamp(m.visCount(), m.listRows())
}

func (m model) drillDown() (tea.Model, tea.Cmd) {
	m.refreshedAt = time.Time{}
	switch m.view {
	case viewProgs:
		i := m.progPane.cur
		if i < 0 || i >= len(m.visProgs) {
			return m, nil
		}
		m.curProg = m.visProgs[i]
		m.view = viewMaps
		m.maps, m.visMaps = nil, nil
		m.mapFilter.SetValue("")
		m.mapPane = pane{}
		return m, tea.Batch(m.loadMapsCmd(), m.loadHolders())

	case viewMaps:
		row, ok := m.curMapRow()
		if !ok {
			return m, nil
		}
		m.curMap = row
		if m.curMap.Err != nil {
			m.err = m.curMap.Err
			return m, nil
		}
		m.view = viewEntries
		m.err = nil
		m.keyFilter.SetValue("")
		return m, tea.Batch(m.startEntries(), m.loadHolders())

	case viewEntries:
		if m.visCount() == 0 {
			return m, nil
		}
		m.view = viewDetail
		m.detailIdx, m.detailGone = m.visAt(m.entryPane.cur), false
		m.detailPane = pane{}
		m.setDetail(m.renderEntry(m.detailIdx))
		return m, nil
	}
	return m, nil
}

func (m *model) setDetail(content string) {
	m.detailLines = strings.Split(strings.TrimRight(content, "\n"), "\n")
	m.detailPane.off = max(0, min(m.detailPane.off, len(m.detailLines)-m.detailRows()))
}

// --- screens ---

// curPane is the scroll state of the current screen.
func (m *model) curPane() *pane {
	switch m.view {
	case viewProgs:
		return &m.progPane
	case viewMaps:
		return &m.mapPane
	case viewEntries:
		return &m.entryPane
	}
	return &m.detailPane
}

// headerLines are the full (untruncated) info lines above the current
// screen's list; they scroll horizontally with it.
func (m model) headerLines() []string {
	switch m.view {
	case viewMaps:
		if m.allMaps {
			return nil
		}
		return []string{labelStyle.Render("attached: ") + attachedOrNone(m.curProg.Attached) +
			crumbStyle.Render("  •  ") + labelStyle.Render("processes: ") + m.holdersText()}
	case viewEntries:
		return []string{
			crumbStyle.Render(fmt.Sprintf("type=%s key=%dB value=%dB max_entries=%d",
				m.curMap.Type, m.curMap.KeySize, m.curMap.ValueSize, m.curMap.MaxEntries)),
			labelStyle.Render("programs: ") + m.mapUsers(),
			labelStyle.Render("processes: ") + m.holdersText(),
		}
	case viewDetail:
		if !m.perCPUDetail() {
			return nil
		}
		kf, _ := m.activeFormats()
		lines := []string{
			crumbStyle.Render(fmt.Sprintf("map %d %q (%s)  entry #%d", m.curMap.ID, m.curMap.Name, m.curMap.Type, m.detailIdx)),
			labelStyle.Render("key: ") + formatOrHexNoted(kf, m.store.key(m.detailIdx), m.linkNote(0, m.detailIdx)),
		}
		if m.detailGone {
			lines = append(lines, errStyle.Render("this key no longer exists in the map; showing the last value read"))
		}
		return lines
	}
	return nil
}

// perCPUDetail reports whether the entry view shows a per-CPU table rather
// than text: one row per CPU (plus Σ), one column per value field.
func (m model) perCPUDetail() bool {
	return m.view == viewDetail && isPerCPU(m.curMap.Type) && m.store.total > m.detailIdx
}

// cpuTable lays out the per-CPU values of the entry being viewed.
func (m model) cpuTable() tableSpec {
	vals := m.store.values(m.detailIdx)
	_, vf := m.activeFormats()
	w := max(20, m.width-2)

	if vf == nil {
		cols := fitColumns(w, []colSpec{{"CPU", 4, 0}, {"Value (hex)", 24, 3}, {"Value", 14, 1}})
		row := func(r int) []string {
			if r == 0 {
				sum := ""
				if s, ok := sumPerCPU(vals); ok {
					sum = fmt.Sprint(s)
				}
				return []string{"Σ", "", sum}
			}
			v := vals[r-1]
			return []string{fmt.Sprint(r - 1), hexBytes(v, 0), shortDecode(v)}
		}
		return tableSpec{cols: cols, n: len(vals) + 1, row: row}
	}

	names, _ := vf.columns(vals[0])
	specs := []colSpec{{"CPU", 4, 0}}
	for _, n := range names {
		specs = append(specs, colSpec{n, max(8, len(n)), 1})
	}
	sum := vf.sumPerCPU(vals)
	row := func(r int) []string {
		label, data := "Σ", sum
		if r > 0 {
			label, data = fmt.Sprint(r-1), vals[r-1]
		}
		_, values := vf.columns(data)
		return append([]string{label}, values...)
	}
	return tableSpec{cols: fitColumns(w, specs), n: len(vals) + 1, row: row}
}

// hasInputLine reports whether the screen reserves a line for its filter.
func (m model) hasInputLine() bool { return m.view != viewDetail }

// listRows is how many list rows fit under the header lines, the filter line
// and the column titles (2 lines) in the body (height - title/status/help).
func (m model) listRows() int {
	used := len(m.headerLines()) + 2
	if m.hasInputLine() {
		used++
	}
	return max(2, m.height-3-used)
}

func (m model) detailRows() int { return max(2, m.height-3) }

// table describes the current screen's list, if it has one.
func (m model) table() (tableSpec, bool) {
	switch m.view {
	case viewProgs:
		empty := "(no programs)"
		if m.progsLoading {
			empty = "loading…"
		}
		return tableSpec{cols: m.progCols, n: len(m.visProgs), empty: empty,
			row: func(i int) []string { return progFields(m.visProgs[i]) }}, true
	case viewMaps:
		empty := "this program does not reference any maps"
		switch {
		case m.mapsLoading:
			empty = "loading…"
		case m.mapFilter.Value() != "":
			empty = "(no maps match)"
		case m.allMaps:
			empty = "(no maps)"
		}
		return tableSpec{cols: m.mapCols, n: len(m.visMaps), empty: empty,
			row: func(i int) []string { return m.mapFields(m.maps[m.visMaps[i]]) }}, true
	case viewEntries:
		empty := "(no entries)"
		switch {
		case m.loading || m.searching:
			empty = "loading…"
		case !m.query.empty():
			empty = "(no key matches)"
		}
		return tableSpec{cols: m.entryColumns(), n: m.visCount(), empty: empty,
			row: func(r int) []string { return m.entryFields(m.visAt(r)) }}, true
	case viewDetail:
		if m.perCPUDetail() {
			return m.cpuTable(), true
		}
	}
	return tableSpec{}, false
}

// overflow is how far the current screen can scroll right: enough to show
// the end of the widest header line, cell or detail line on screen.
func (m model) overflow() int {
	width := max(10, m.width-1)
	over := 0
	for _, l := range m.headerLines() {
		over = max(over, lineOverflow(l, width))
	}
	if t, ok := m.table(); ok {
		over = max(over, t.overflow(m.paneState(), m.listRows()))
	} else if m.view == viewDetail {
		p := m.detailPane
		for _, l := range m.detailLines[p.off:min(len(m.detailLines), p.off+m.detailRows())] {
			over = max(over, lineOverflow(l, width))
		}
	}
	return over
}

// paneState returns a copy of the current screen's scroll state.
func (m model) paneState() pane { return *m.curPane() }

func (m *model) hscroll(delta int) {
	p := m.curPane()
	p.hOff = max(0, min(p.hOff+delta, m.overflow()))
}

// renderEntryList draws the entries table (also used by tests).
func (m model) renderEntryList() string {
	t, _ := m.table()
	return t.render(m.entryPane, m.listRows())
}

func progFields(p progRow) []string {
	name := p.Name
	if name == "" {
		name = "<anon>"
	}
	return []string{fmt.Sprint(p.ID), name, p.Type.String(), fmt.Sprint(len(p.MapIDs)), p.Tag, p.Attached}
}

func (m model) mapFields(mp mapRow) []string {
	if mp.Err != nil {
		return []string{fmt.Sprint(mp.ID), "<error>", mp.Err.Error(), "", "", "", "", "", ""}
	}
	return []string{
		fmt.Sprint(mp.ID), mp.Name, mp.Type.String(),
		fmt.Sprint(mp.KeySize), fmt.Sprint(mp.ValueSize), fmt.Sprint(mp.MaxEntries),
		countCell(mp), fmt.Sprintf("0x%x", mp.Flags), m.formatCell(mp),
	}
}

func (m model) holdersText() string {
	if !m.holdersDone {
		return "finding…"
	}
	if len(m.holders) == 0 {
		return "none"
	}
	return strings.Join(m.holders, ", ")
}

func attachedOrNone(s string) string {
	if s == "" {
		return "none found"
	}
	return s
}

// mapUsers lists the loaded programs using curMap.
func (m model) mapUsers() string {
	var users []string
	for _, p := range m.progs {
		if slices.Contains(p.MapIDs, m.curMap.ID) {
			users = append(users, fmt.Sprintf("%s (%d)", p.Name, p.ID))
		}
	}
	if len(users) == 0 {
		return "none"
	}
	return strings.Join(users, ", ")
}

func countCell(mp mapRow) string {
	switch {
	case errors.Is(mp.CountErr, errNotIterable):
		return "-"
	case mp.CountErr != nil:
		return "err"
	case mp.Count < 0:
		return "counting…"
	}
	return fmt.Sprint(mp.Count)
}

func (m model) entryColumns() []column {
	cols := m.entryCol
	if kf, vf := m.activeFormats(); kf != nil || vf != nil {
		cols = m.entryColFmt
	}
	// Linked fields show their translation in place: say so in the title.
	keyLinked, valueLinked := linkedSide(m.links, 0), linkedSide(m.links, 1)
	if !keyLinked && !valueLinked {
		return cols
	}
	cols = slices.Clone(cols)
	for i, c := range cols {
		if c.title == "Key" && keyLinked || c.title == "Value" && valueLinked {
			cols[i].title += " (linked)"
		}
	}
	return cols
}

// entryFields returns the full, untruncated text of each column for entry i;
// cell() cuts it to the column width and ←/→ scroll through the rest.
// Linked fields are followed by their translation ("backend_id=3→{…}").
func (m model) entryFields(i int) []string {
	key, vals := m.store.key(i), m.store.values(i)
	kn, vn := m.linkNote(0, i), m.linkNote(1, i)
	perCPU := isPerCPU(m.curMap.Type)
	if kf, vf := m.activeFormats(); kf != nil || vf != nil {
		return []string{fmt.Sprint(i), formatOrHexNoted(kf, key, kn), formatValues(vf, vals, perCPU, vn)}
	}
	var val, dec string
	if perCPU {
		val = fmt.Sprintf("[%d CPUs] %s", len(vals), hexBytes(vals[0], 0))
		if sum, ok := sumPerCPU(vals); ok {
			dec = fmt.Sprintf("Σ %d", sum)
		}
	} else {
		val = hexBytes(vals[0], 0)
		dec = shortDecode(vals[0])
	}
	return []string{fmt.Sprint(i), hexBytes(key, 0), shortDecode(key) + kn.of(""), val, dec + vn.of("")}
}

func (m model) renderEntry(i int) string {
	key, vals := m.store.key(i), m.store.values(i)
	kf, vf := m.activeFormats()
	var b strings.Builder
	fmt.Fprintf(&b, "Map %d %q (%s)  entry #%d\n\n", m.curMap.ID, m.curMap.Name, m.curMap.Type, i)
	if m.detailGone {
		b.WriteString(errStyle.Render("this key no longer exists in the map; showing the last value read") + "\n\n")
	}
	kn, vn := m.linkNote(0, i), m.linkNote(1, i)
	b.WriteString(renderBytes(fmt.Sprintf("KEY (%d bytes)", len(key)), kf, key, kn) + "\n")

	if isPerCPU(m.curMap.Type) {
		if vf != nil {
			b.WriteString(renderBytes(fmt.Sprintf("VALUE Σ over %d CPUs", len(vals)), vf, vf.sumPerCPU(vals), vn) + "\n")
		} else if sum, ok := sumPerCPU(vals); ok {
			fmt.Fprintf(&b, "VALUE sum over %d CPUs = %d\n\n", len(vals), sum)
		}
		for cpu, v := range vals {
			b.WriteString(renderBytes(fmt.Sprintf("VALUE cpu%d (%d bytes)", cpu, len(v)), vf, v, nil) + "\n")
		}
	} else {
		v := vals[0]
		b.WriteString(renderBytes(fmt.Sprintf("VALUE (%d bytes)", len(v)), vf, v, vn))
	}
	return b.String()
}

// renderBytes renders a key or value for the detail view: one line per
// field with a format, a hex dump otherwise.
func renderBytes(title string, t *ctype, data []byte, n note) string {
	if t != nil {
		return wholeNote(t, title, n) + "\n  " + strings.Join(t.linesNoted("", data, n), "\n  ") + "\n"
	}
	if d := decode(data); d != "" {
		title += "  = " + d
	}
	return title + n.of("") + "\n" + hexDump(data)
}

// formatOrHexNoted is formatOrHex with notes: after each field of a format,
// and after the whole text for the key or value itself (path "").
func formatOrHexNoted(t *ctype, b []byte, n note) string {
	if t == nil {
		return formatOrHex(nil, b) + n.of("")
	}
	return wholeNote(t, t.formatNoted(b, n), n)
}

// wholeNote appends the note of a whole struct; the note of a whole scalar
// is already after its value.
func wholeNote(t *ctype, s string, n note) string {
	if t != nil && (t.kind == kStruct || t.kind == kUnion) {
		if w := n.of(""); w != "" {
			return s + " " + w
		}
	}
	return s
}

func formatOrHex(t *ctype, b []byte) string {
	if t != nil {
		return t.format(b)
	}
	if d := shortDecode(b); d != "" {
		return hexBytes(b, 0) + " (" + d + ")"
	}
	return hexBytes(b, 0)
}

func formatValues(t *ctype, vals [][]byte, perCPU bool, n note) string {
	switch {
	case !perCPU:
		return formatOrHexNoted(t, vals[0], n)
	case t != nil && (t.kind == kStruct || t.kind == kUnion):
		// Fields are summed per field; braces read better than Σ in front
		// of a list of fields.
		return wholeNote(t, "{"+t.formatNoted(t.sumPerCPU(vals), n)+"}", n)
	case t != nil:
		return "Σ " + t.formatNoted(t.sumPerCPU(vals), n)
	}
	if sum, ok := sumPerCPU(vals); ok {
		return fmt.Sprintf("Σ %d [%d CPUs]", sum, len(vals)) + n.of("")
	}
	return fmt.Sprintf("[%d CPUs] %s", len(vals), hexBytes(vals[0], 0)) + n.of("")
}

// activeFormats returns the formats to apply to curMap's keys and values:
// nil (shown as hex) when undefined or not matching the map's sizes (a
// hand-edited formats.json, or a map that changed layout).
func (m model) activeFormats() (key, value *ctype) { return m.formatsFor(m.curMap) }

// formatsFor is activeFormats for any map (e.g. a link target).
func (m model) formatsFor(mp mapRow) (key, value *ctype) {
	if m.formats == nil {
		return nil, nil
	}
	c := m.formats.get(mp)
	if c.key != nil && c.key.size == int(mp.KeySize) {
		key = c.key
	}
	if c.value != nil && c.value.size == int(mp.ValueSize) {
		value = c.value
	}
	return key, value
}

// formatTarget is the map the "e" key edits the format of.
func (m model) formatTarget() (mapRow, bool) {
	switch m.view {
	case viewMaps:
		if r, ok := m.curMapRow(); ok && r.Err == nil {
			return r, true
		}
	case viewEntries, viewDetail:
		return m.curMap, true
	}
	return mapRow{}, false
}

func (m model) formatCell(mp mapRow) string {
	if m.formats == nil {
		return ""
	}
	c := m.formats.get(mp)
	switch {
	case c.key != nil && c.value != nil:
		return "key+val"
	case c.key != nil:
		return "key"
	case c.value != nil:
		return "val"
	}
	return ""
}

// formatsChanged re-renders everything that depends on formats.
func (m *model) formatsChanged() tea.Cmd {
	if m.view == viewDetail {
		m.setDetail(m.renderEntry(m.detailIdx))
	}
	var cmds []tea.Cmd
	if m.view >= viewEntries {
		// Linked fields are found through the format.
		cmds = append(cmds, m.resolveLinks())
	}
	if !m.query.empty() {
		cur := m.entryPane.cur
		cmds = append(cmds, m.applyKeyFilter())
		m.pendingCur = cur
	}
	return tea.Batch(cmds...)
}

func (m *model) resize() {
	w := max(20, m.width-2)
	m.progCols = fitColumns(w, []colSpec{
		{"ID", 6, 0}, {"Name", 16, 1}, {"Type", 13, 0}, {"Maps", 4, 0}, {"Tag", 16, 0}, {"Attached", 12, 4},
	})
	m.mapCols = fitColumns(w, []colSpec{
		{"ID", 6, 0}, {"Name", 14, 2}, {"Type", 12, 1}, {"Key", 4, 0}, {"Value", 5, 0}, {"MaxEntries", 10, 0}, {"Entries", 10, 0}, {"Flags", 5, 0}, {"Format", 7, 0},
	})
	m.entryCol = fitColumns(w, []colSpec{
		{"#", 8, 0}, {"Key (hex)", 20, 2}, {"Key", 12, 1}, {"Value (hex)", 30, 3}, {"Value", 14, 1},
	})
	m.entryColFmt = fitColumns(w, []colSpec{
		{"#", 8, 0}, {"Key", 30, 1}, {"Value", 30, 1},
	})
	if t, ok := m.table(); ok {
		m.curPane().clamp(t.n, m.listRows())
	}
}

func (m model) View() string {
	if m.width == 0 {
		return "loading…"
	}
	var b strings.Builder

	crumbs := []string{"programs"}
	if m.allMaps {
		crumbs = []string{"all maps"}
	} else if m.view >= viewMaps {
		crumbs = append(crumbs, fmt.Sprintf("prog %d %s", m.curProg.ID, m.curProg.Name))
	}
	if m.view >= viewEntries {
		crumbs = append(crumbs, fmt.Sprintf("map %d %s", m.curMap.ID, m.curMap.Name))
	}
	if m.view >= viewDetail {
		crumbs = append(crumbs, "entry")
	}
	title := "eBPF explorer"
	b.WriteString(titleStyle.Render(title) + " " + crumbStyle.Render(strings.Join(crumbs, " › ")) + "\n")

	var body []string
	p := m.paneState()
	width := max(10, m.width-1)
	for _, l := range m.headerLines() {
		body = append(body, scrollLine(l, p.hOff, width))
	}
	if m.hasInputLine() {
		f := *m.activeFilter()
		if m.editing || f.Value() != "" {
			body = append(body, f.View())
		} else {
			body = append(body, "")
		}
	}
	if t, ok := m.table(); ok {
		body = append(body, t.render(p, m.listRows()))
	} else if m.view == viewDetail {
		for _, l := range m.detailLines[p.off:min(len(m.detailLines), p.off+m.detailRows())] {
			body = append(body, scrollLine(l, p.hOff, width))
		}
	}
	content := strings.Join(body, "\n")
	if m.fmtEdit != nil {
		content = m.fmtEdit.view(m.width-2, m.height-3)
	} else if m.code != nil {
		content = m.codeContent()
	}
	// Fixed-height body so the footer doesn't jump while data streams in.
	b.WriteString(lipgloss.NewStyle().Height(m.height - 3).MaxHeight(m.height - 3).Render(content))

	b.WriteString("\n")
	switch {
	case m.code != nil && m.code.err != nil:
		b.WriteString(errStyle.Render("error: " + m.code.err.Error()))
	case m.code != nil:
		b.WriteString(statusStyle.Render(m.codeStatus()))
	case m.err != nil:
		b.WriteString(errStyle.Render("error: " + m.err.Error()))
	case m.view >= viewEntries && m.loadErr != nil:
		b.WriteString(errStyle.Render(fmt.Sprintf("error after %d entries: %v", m.store.total, m.loadErr)))
	default:
		b.WriteString(statusStyle.Render(m.status()))
	}
	b.WriteString("\n" + m.help())
	return b.String()
}

func (m model) status() string {
	parts := []string{m.scopeStatus()}
	if m.view >= viewEntries {
		parts = append(parts, m.modeTag())
	}
	if off := m.paneState().hOff; off > 0 {
		parts = append(parts, fmt.Sprintf("scrolled →%d", off))
	}
	if !m.refreshedAt.IsZero() {
		parts = append(parts, "refreshed "+m.refreshedAt.Format("15:04:05"))
	}
	parts = slices.DeleteFunc(parts, func(s string) bool { return s == "" })
	return strings.Join(parts, " • ")
}

func (m model) scopeStatus() string {
	switch m.view {
	case viewProgs:
		if m.progsLoading {
			return "loading programs…"
		}
		return fmt.Sprintf("%d programs", len(m.progs))
	case viewMaps:
		switch {
		case m.mapsLoading:
			return "loading maps…"
		case m.mapFilter.Value() != "":
			return fmt.Sprintf("%d/%d maps", len(m.visMaps), len(m.maps))
		}
		return fmt.Sprintf("%d maps", len(m.maps))
	case viewDetail:
		if m.entryReload {
			return "refreshing entry…"
		}
		return ""
	}

	var parts []string
	if m.loading {
		s := fmt.Sprintf("loading entries… %d", m.store.total)
		if m.curMap.Count > 0 {
			s += fmt.Sprintf(" / ~%d (%d%%)", m.curMap.Count, min(100, m.store.total*100/m.curMap.Count))
		}
		parts = append(parts, s)
	} else {
		parts = append(parts, fmt.Sprintf("%d entries", m.store.total))
	}
	switch {
	case m.searching:
		parts = append(parts, "searching…")
	case !m.query.empty():
		parts = append(parts, fmt.Sprintf("%d match", len(m.visible)))
	}
	if n := m.visCount(); n > 0 {
		parts = append(parts, fmt.Sprintf("row %d/%d", m.entryPane.cur+1, n))
	}
	return strings.Join(parts, " • ")
}

func (m model) modeTag() string {
	if k, v := m.activeFormats(); k == nil && v == nil {
		return "[HEX: no format, press e]"
	}
	return "[FORMAT]"
}

// help renders the footer as "[key] action" pairs.
func (m model) help() string {
	var keys [][2]string
	switch {
	case m.fmtEdit != nil:
		keys = m.fmtEdit.help()
	case m.code != nil:
		keys = m.codeHelp()
	case m.editing:
		keys = [][2]string{{"enter", "apply"}, {"esc", "clear"}}
	case m.view == viewProgs:
		keys = [][2]string{{"↑/↓", "move"}, {"←/→", "scroll"}, {"enter", "open"}, {"d", "code"}, {"/", "filter"}, {"m", "all maps"}, {"r", "refresh programs"}, {"q", "quit"}}
	case m.view == viewMaps && m.allMaps:
		keys = [][2]string{{"↑/↓", "move"}, {"←/→", "scroll"}, {"enter", "open"}, {"/", "filter"}, {"e", "edit format"}, {"p", "programs"}, {"r", "refresh maps"}, {"q", "quit"}}
	case m.view == viewMaps:
		keys = [][2]string{{"↑/↓", "move"}, {"←/→", "scroll"}, {"enter", "open"}, {"d", "code"}, {"/", "filter"}, {"e", "edit format"}, {"esc", "back"}, {"r", "refresh maps"}, {"q", "quit"}}
	case m.view == viewEntries:
		keys = [][2]string{{"↑/↓ pgup/pgdn g/G", "move"}, {"←/→", "scroll"}, {"enter", "open"}, {"/", "search"}, {"e", "edit format"}, {"esc", "back"}, {"r", "refresh map"}, {"q", "quit"}}
	case m.view == viewDetail && m.perCPUDetail():
		keys = [][2]string{{"↑/↓", "move"}, {"←/→", "scroll"}, {"e", "edit format"}, {"esc", "back"}, {"r", "refresh entry"}, {"q", "quit"}}
	case m.view == viewDetail:
		keys = [][2]string{{"↑/↓", "scroll"}, {"←/→", "scroll"}, {"e", "edit format"}, {"esc", "back"}, {"r", "refresh entry"}, {"q", "quit"}}
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = helpKeyStyle.Render("["+k[0]+"]") + " " + helpStyle.Render(k[1])
	}
	return strings.Join(parts, helpStyle.Render("  "))
}

func main() {
	maps := flag.Bool("maps", false, "start on the list of all maps instead of the programs")
	flag.BoolVar(&useGlobalConfig, "global-config", false,
		"load/store formats in $XDG_CONFIG_HOME/ebpfexplorer/formats.json instead of "+localFormatsFile+" next to the binary")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "warning: not running as root; listing BPF objects usually needs CAP_SYS_ADMIN/CAP_BPF")
	}

	p := tea.NewProgram(initialModel(*maps), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
