package internal

// Links translate IDs: a field of an entry (or its whole key or value) is
// looked up as a key in another map, and the value found there is shown
// next to the entry. E.g. a flows map holding a backend_id, linked to a
// backends map (backend_id → ip, port), shows each flow's backend address.
//
// Links are saved with the formats, by map name on both ends:
//
//	"flows": { "key": "...", "links": { "key.backend_id": "backends" } }

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf"
)

// linkSource is a part of an entry that can be linked.
type linkSource struct {
	path string // "key", "value", "key.backend_id", "value.slots[0].id"
	side int    // 0 = key, 1 = value
	off  int
	size int    // 0 for a saved link whose field is not in the format anymore
	t    *ctype // nil when the side has no format: raw bytes
}

// linkSources lists what can be linked in mp's entries: the whole key and
// value, then every field of their formats. Per-CPU values are linked
// through CPU 0's copy.
func linkSources(mp mapRow, kf, vf *ctype) []linkSource {
	var out []linkSource
	for side, t := range []*ctype{kf, vf} {
		name := []string{"key", "value"}[side]
		size := []uint32{mp.KeySize, mp.ValueSize}[side]
		out = append(out, linkSource{path: name, side: side, size: int(size), t: t})
		if t == nil || (t.kind != kStruct && t.kind != kUnion) {
			continue
		}
		for _, l := range t.leaves("", 0) {
			out = append(out, linkSource{path: name + "." + l.path, side: side, off: l.off, size: l.t.size, t: l.t})
		}
	}
	return out
}

func (s linkSource) bytes(key []byte, vals [][]byte) []byte {
	b := key
	if s.side == 1 {
		b = vals[0]
	}
	return b[s.off:][:s.size]
}

// text renders the source's own value, e.g. "3" for backend_id.
func (s linkSource) text(b []byte) string {
	if s.t == nil {
		return hexBytes(b, 0)
	}
	return s.t.formatValue(b)
}

// label is the short name shown in the entries table: the field name, or
// "key"/"value" for a whole side.
func (s linkSource) label() string {
	if _, field, ok := strings.Cut(s.path, "."); ok {
		return field
	}
	return s.path
}

// fits reports whether the source can be looked up in a map with keySize
// byte keys: same size, or a smaller host-order integer that is widened
// (a __u16 id used as a __u32 key).
func (s linkSource) fits(keySize int) bool {
	return s.size == keySize || s.widens(keySize)
}

func (s linkSource) widens(keySize int) bool {
	t := s.t
	return t != nil && t.kind == kInt && !t.bigEndian && !t.char &&
		s.size < keySize && slices.Contains([]int{2, 4, 8}, keySize)
}

// lookupKey turns the source's bytes into a keySize-byte key.
func (s linkSource) lookupKey(b []byte, keySize int) []byte {
	if !s.widens(keySize) {
		return b
	}
	v := s.t.uint(b)
	if s.t.signed {
		shift := 64 - 8*s.size
		v = uint64(int64(v<<shift) >> shift)
	}
	out := make([]byte, keySize)
	intType(keySize, false).putUint(out, v)
	return out
}

// linkTarget is an open map that links look keys up in.
type linkTarget struct {
	row    mapRow
	lookup func(key []byte) ([][]byte, error)
	close  func()
}

func openLinkTarget(row mapRow) (*linkTarget, error) {
	mp, err := ebpf.NewMapFromID(row.ID)
	if err != nil {
		return nil, err
	}
	return &linkTarget{
		row:    row,
		lookup: func(k []byte) ([][]byte, error) { return lookupIn(mp, k) },
		close:  func() { mp.Close() },
	}, nil
}

// mapLink is a saved link of the map being viewed, ready to translate entries.
type mapLink struct {
	src    linkSource
	name   string      // target map name, as saved
	target *linkTarget // nil when err is set
	err    error
	format *ctype // the target's value format, set once resolved

	// cache holds the lookups done so far by key: rows are rendered on every
	// frame, the target map is only read again on refresh. Key searches
	// look up from their own goroutine.
	mu    sync.Mutex
	cache map[string]lookupResult
}

type lookupResult struct {
	vals [][]byte
	err  error
}

const maxLinkCache = 100_000

// lookup translates one entry: it returns the source's bytes and what the
// target map holds for them.
func (l *mapLink) lookup(key []byte, vals [][]byte) ([]byte, lookupResult) {
	if l.err != nil {
		return nil, lookupResult{err: l.err}
	}
	b := l.src.bytes(key, vals)
	k := l.src.lookupKey(b, int(l.target.row.KeySize))
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.cache[string(k)]; ok {
		return b, r
	}
	if len(l.cache) >= maxLinkCache {
		clear(l.cache)
	}
	v, err := l.target.lookup(k)
	r := lookupResult{v, err}
	l.cache[string(k)] = r
	return b, r
}

func closeLinks(links []*mapLink) {
	for _, l := range links {
		if l.target != nil {
			l.target.close()
		}
	}
}

// pickMap finds the map called name: the one prog uses if any (several
// loaded programs may each have their own copy), else the newest.
func pickMap(name string, all []mapRow, prog []ebpf.MapID) (mapRow, bool) {
	var best mapRow
	found := false
	for _, r := range all {
		if r.Name != name {
			continue
		}
		if slices.Contains(prog, r.ID) {
			return r, true
		}
		if !found || r.ID > best.ID {
			best, found = r, true
		}
	}
	return best, found
}

func sizeMismatch(s linkSource, target mapRow) error {
	return fmt.Errorf("%s is %dB but %q keys are %dB", s.path, s.size, target.Name, target.KeySize)
}

// buildLinks resolves saved links (field path → map name) against the
// loaded maps, in the order of sources; links to fields the format no longer
// has come last, with an error.
func buildLinks(defs map[string]string, sources []linkSource, all []mapRow, prog []ebpf.MapID,
	open func(mapRow) (*linkTarget, error)) []*mapLink {
	var out []*mapLink
	for _, s := range sources {
		name, ok := defs[s.path]
		if !ok {
			continue
		}
		l := &mapLink{src: s, name: name, cache: map[string]lookupResult{}}
		row, ok := pickMap(name, all, prog)
		switch {
		case !ok:
			l.err = fmt.Errorf("no map named %q is loaded", name)
		case !s.fits(int(row.KeySize)):
			l.err = sizeMismatch(s, row)
		default:
			l.target, l.err = open(row)
		}
		out = append(out, l)
	}
	for _, path := range staleLinks(defs, sources) {
		out = append(out, &mapLink{src: linkSource{path: path}, name: defs[path],
			err: fmt.Errorf("%s is not in the current format", path)})
	}
	return out
}

// staleLinks are the saved links whose field is not in sources, sorted.
func staleLinks(defs map[string]string, sources []linkSource) []string {
	var out []string
	for path := range defs {
		if !slices.ContainsFunc(sources, func(s linkSource) bool { return s.path == path }) {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}

// --- model ---

type linksResolved struct {
	gen   int
	links []*mapLink
	err   error
}

type mapsListed struct {
	rows []mapRow
	err  error
}

func listMapsCmd() tea.Msg {
	rows, err := listAllMaps()
	return mapsListed{rows, err}
}

// resolveLinks opens the targets of curMap's links in the background. The
// links in use stay until the new ones arrive.
func (m *model) resolveLinks() tea.Cmd {
	m.linkGen++
	var defs map[string]string
	if m.formats != nil {
		defs = m.formats.def(m.curMap).Links
	}
	if len(defs) == 0 {
		closeLinks(m.links)
		m.links = nil
		return nil
	}
	kf, vf := m.activeFormats()
	sources := linkSources(m.curMap, kf, vf)
	gen, prog := m.linkGen, m.curProg.MapIDs
	return func() tea.Msg {
		all, err := listAllMaps()
		return linksResolved{gen, buildLinks(defs, sources, all, prog, openLinkTarget), err}
	}
}

func (m model) onLinksResolved(msg linksResolved) (tea.Model, tea.Cmd) {
	if msg.gen != m.linkGen {
		closeLinks(msg.links)
		return m, nil
	}
	closeLinks(m.links)
	m.links = msg.links
	errs := []error{msg.err}
	for _, l := range m.links {
		if l.target != nil {
			_, l.format = m.formatsFor(l.target.row)
		} else if l.src.size > 0 { // links to fields gone from the format are expected
			errs = append(errs, fmt.Errorf("link %s: %w", l.src.path, l.err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		m.err = err
	}
	if m.view == viewDetail {
		m.setDetail(m.renderEntry(m.detailIdx))
	}
	if m.query.empty() {
		return m, nil
	}
	// Search the translations too.
	cur := m.entryPane.cur
	cmd := m.applyKeyFilter()
	m.pendingCur = cur
	return m, cmd
}

// dropLinks closes the links when leaving the map; in-flight resolutions
// are closed on arrival.
func (m *model) dropLinks() {
	m.linkGen++
	closeLinks(m.links)
	m.links = nil
}

// clearLinkCaches makes the next render read the target maps again.
func (m *model) clearLinkCaches() {
	for _, l := range m.links {
		l.mu.Lock()
		clear(l.cache)
		l.mu.Unlock()
	}
}

// value renders what a lookup found in the target map, on one line.
func (l *mapLink) value(r lookupResult) string {
	switch {
	case errors.Is(r.err, ebpf.ErrKeyNotExist):
		return "(not found)"
	case r.err != nil:
		return "✗ " + r.err.Error()
	case isPerCPU(l.target.row.Type):
		return formatValues(l.format, r.vals, true, nil)
	case l.format != nil:
		return l.format.formatValue(r.vals[0]) // braces around structs
	}
	return formatOrHex(nil, r.vals[0])
}

// linkedSide reports whether a resolved link translates fields of side
// (0 = key, 1 = value).
func linkedSide(links []*mapLink, side int) bool {
	return slices.ContainsFunc(links, func(l *mapLink) bool { return l.target != nil && l.src.side == side })
}

// linkNote follows each linked field of an entry's key (side 0) or value
// with its translation: "backend_id=3→{ip=10.0.0.5 port=80}". It is nil
// when nothing on that side is linked.
func linkNote(links []*mapLink, side int, key []byte, vals [][]byte) note {
	if !linkedSide(links, side) {
		return nil
	}
	name := []string{"key", "value"}[side]
	return func(path string) string {
		if path != "" {
			path = name + "." + path
		} else {
			path = name
		}
		for _, l := range links {
			if l.target != nil && l.src.side == side && l.src.path == path {
				_, r := l.lookup(key, vals)
				return "→" + l.value(r)
			}
		}
		return ""
	}
}

func (m model) linkNote(side, i int) note {
	return linkNote(m.links, side, m.store.key(i), m.store.values(i))
}
