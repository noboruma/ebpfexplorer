package main

// A small C declaration parser used to pretty-print map keys and values.
//
// Accepted input (one per key / value of a map):
//
//	struct { __u32 ip; __u16 port; __u8 proto; }        named or anonymous structs/unions
//	__u32 a; __u64 b;                                    a bare field list is an implicit struct
//	__u64                                                a single scalar
//	struct { char comm[16]; ipv4 saddr; mac src; } __attribute__((packed))
//
// Layout follows the x86-64/arm64 SysV ABI (natural alignment, packed and
// aligned(N) attributes honoured). Besides the usual C and kernel integer
// types, a few display-only types are understood:
//
//	ipv4, ipv6, mac      addresses in network order (4/16/6 bytes)
//	x8 x16 x32 x64       unsigned integers printed in hex
//	__be16 __be32 __be64 big-endian integers (printed in host order)

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

type kind int

const (
	kInt kind = iota
	kBool
	kFloat
	kPtr
	kIP4
	kIP6
	kMAC
	kArray
	kStruct
	kUnion
)

type ctype struct {
	kind        kind
	size, align int

	signed, bigEndian, hex, char bool // kInt flavours

	elem *ctype // kArray
	n    int

	fields []field // kStruct, kUnion
}

type field struct {
	name string // empty for anonymous struct/union members
	t    *ctype
	off  int
}

func intType(size int, signed bool) *ctype {
	return &ctype{kind: kInt, size: size, align: size, signed: signed}
}

var scalarTypes = func() map[string]*ctype {
	m := map[string]*ctype{
		"bool":   {kind: kBool, size: 1, align: 1},
		"_Bool":  {kind: kBool, size: 1, align: 1},
		"float":  {kind: kFloat, size: 4, align: 4},
		"double": {kind: kFloat, size: 8, align: 8},
		"ipv4":   {kind: kIP4, size: 4, align: 4},
		"ipv6":   {kind: kIP6, size: 16, align: 4},
		"mac":    {kind: kMAC, size: 6, align: 1},
		"char":   {kind: kInt, size: 1, align: 1, signed: true, char: true},

		"size_t":    intType(8, false),
		"ssize_t":   intType(8, true),
		"uintptr_t": intType(8, false),
	}
	for _, bits := range []int{8, 16, 32, 64} {
		n := bits / 8
		for _, name := range []string{"__u%d", "u%d", "uint%d_t", "__le%d"} {
			m[fmt.Sprintf(name, bits)] = intType(n, false)
		}
		for _, name := range []string{"__s%d", "s%d", "int%d_t"} {
			m[fmt.Sprintf(name, bits)] = intType(n, true)
		}
		if bits > 8 {
			m[fmt.Sprintf("__be%d", bits)] = &ctype{kind: kInt, size: n, align: n, bigEndian: true}
		}
		m[fmt.Sprintf("x%d", bits)] = &ctype{kind: kInt, size: n, align: n, hex: true}
	}
	return m
}()

// --- tokenizer ---

func tokenize(src string) ([]string, error) {
	var toks []string
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case unicode.IsSpace(rune(c)):
			i++
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, errors.New("unterminated comment")
			}
			i += end + 4
		case c == '_' || unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)):
			j := i
			for j < len(src) && (src[j] == '_' || unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j]))) {
				j++
			}
			toks = append(toks, src[i:j])
			i = j
		case strings.ContainsRune("{}[]();,*:", rune(c)):
			toks = append(toks, string(c))
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	return toks, nil
}

// --- parser ---

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *parser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) expect(t string) error {
	if got := p.next(); got != t {
		if got == "" {
			got = "end of input"
		}
		return fmt.Errorf("expected %q, got %q", t, got)
	}
	return nil
}

// parseCType parses a key/value format definition.
func parseCType(src string) (*ctype, error) {
	toks, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("empty definition")
	}
	p := &parser{toks: toks}

	var t *ctype
	if toks[0] != "struct" && toks[0] != "union" && strings.Contains(src, ";") {
		// Bare field list: treat as the body of an anonymous struct.
		fields, err := p.parseFields("")
		if err != nil {
			return nil, err
		}
		t = layout(kStruct, fields, false, 0)
	} else {
		if t, err = p.parseType(); err != nil {
			return nil, err
		}
		// Optional declarator, e.g. "struct {...} key;" or "ipv4 saddr".
		if p.peek() != "" && p.peek() != ";" {
			isStruct := t.kind == kStruct || t.kind == kUnion
			var name string
			if name, t, err = p.parseDeclarator(t); err != nil {
				return nil, err
			}
			// A named non-struct ("ipv4 saddr") is a one-field struct so the
			// name is shown, exactly like "ipv4 saddr;". A struct's own
			// variable name ("struct {...} key") adds nothing.
			if !isStruct {
				t = layout(kStruct, []field{{name: name, t: t}}, false, 0)
			}
		}
		if p.peek() == ";" {
			p.next()
		}
	}
	if p.peek() != "" {
		return nil, fmt.Errorf("unexpected %q after definition", p.peek())
	}
	if t.size == 0 {
		return nil, errors.New("type has zero size")
	}
	return t, nil
}

func (p *parser) parseType() (*ctype, error) {
	for p.peek() == "const" || p.peek() == "volatile" {
		p.next()
	}
	switch tok := p.peek(); tok {
	case "struct", "union":
		p.next()
		if p.peek() != "{" {
			name := p.next()
			if p.peek() != "{" {
				return nil, fmt.Errorf("%s %s: only inline definitions are supported, write %s %s { ... }", tok, name, tok, name)
			}
		}
		p.next() // {
		fields, err := p.parseFields("}")
		if err != nil {
			return nil, err
		}
		p.next() // }
		packed, aligned, err := p.parseAttributes()
		if err != nil {
			return nil, err
		}
		k := kStruct
		if tok == "union" {
			k = kUnion
		}
		return layout(k, fields, packed, aligned), nil
	case "":
		return nil, errors.New("expected a type, got end of input")
	}
	return p.parseScalar()
}

// parseScalar handles typedef-style names (__u32, ipv4...) and multi-word C
// integer types (unsigned long long int...).
func (p *parser) parseScalar() (*ctype, error) {
	if t, ok := scalarTypes[p.peek()]; ok && !isCIntWord(p.peek()) {
		p.next()
		return t, nil
	}
	var unsigned, signed, short, char bool
	longs := 0
	n := 0
	for isCIntWord(p.peek()) || p.peek() == "const" || p.peek() == "volatile" {
		switch p.next() {
		case "unsigned":
			unsigned = true
		case "signed":
			signed = true
		case "short":
			short = true
		case "long":
			longs++
		case "char":
			char = true
		}
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("unknown type %q", p.peek())
	}
	switch {
	case char && unsigned:
		return intType(1, false), nil
	case char && signed:
		return intType(1, true), nil
	case char:
		return scalarTypes["char"], nil
	case short:
		return intType(2, !unsigned), nil
	case longs > 0:
		return intType(8, !unsigned), nil // LP64: long and long long are 8 bytes
	}
	return intType(4, !unsigned), nil
}

func isCIntWord(s string) bool {
	switch s {
	case "unsigned", "signed", "short", "long", "char", "int":
		return true
	}
	return false
}

// parseFields reads declarations until the closing token ("}" or end).
func (p *parser) parseFields(closing string) ([]field, error) {
	var fields []field
	for p.peek() != closing {
		if p.peek() == "" {
			return nil, fmt.Errorf("expected %q, got end of input", closing)
		}
		t, err := p.parseType()
		if err != nil {
			return nil, err
		}
		if p.peek() == ";" && (t.kind == kStruct || t.kind == kUnion) {
			p.next() // anonymous member: its fields are accessed directly
			fields = append(fields, field{t: t})
			continue
		}
		for {
			name, ft, err := p.parseDeclarator(t)
			if err != nil {
				return nil, err
			}
			_, aligned, err := p.parseAttributes()
			if err != nil {
				return nil, err
			}
			if aligned > ft.align {
				c := *ft
				c.align = aligned
				ft = &c
			}
			fields = append(fields, field{name: name, t: ft})
			if p.peek() != "," {
				break
			}
			p.next()
		}
		if err := p.expect(";"); err != nil {
			return nil, err
		}
	}
	if len(fields) == 0 {
		return nil, errors.New("struct has no fields")
	}
	return fields, nil
}

func (p *parser) parseDeclarator(t *ctype) (string, *ctype, error) {
	for p.peek() == "*" {
		p.next()
		t = &ctype{kind: kPtr, size: 8, align: 8}
	}
	name := p.next()
	if name == "" || !(name[0] == '_' || unicode.IsLetter(rune(name[0]))) {
		return "", nil, fmt.Errorf("expected a field name, got %q", name)
	}
	var dims []int
	for p.peek() == "[" {
		p.next()
		n, err := strconv.ParseInt(p.next(), 0, 32)
		if err != nil || n < 0 {
			return "", nil, fmt.Errorf("%s: invalid array size", name)
		}
		if err := p.expect("]"); err != nil {
			return "", nil, err
		}
		dims = append(dims, int(n))
	}
	// int a[2][3] is an array of 2 arrays of 3 ints: build from the inside.
	for i := len(dims) - 1; i >= 0; i-- {
		t = &ctype{kind: kArray, elem: t, n: dims[i], size: t.size * dims[i], align: t.align}
	}
	if p.peek() == ":" {
		return "", nil, fmt.Errorf("%s: bitfields are not supported", name)
	}
	return name, t, nil
}

// parseAttributes consumes any __attribute__((...)) and reports packed /
// aligned(N).
func (p *parser) parseAttributes() (packed bool, aligned int, err error) {
	for p.peek() == "__attribute__" || p.peek() == "__attribute" {
		p.next()
		if err := p.expect("("); err != nil {
			return false, 0, err
		}
		depth := 1
		for depth > 0 {
			switch tok := p.next(); tok {
			case "":
				return false, 0, errors.New("unterminated __attribute__")
			case "(":
				depth++
			case ")":
				depth--
			case "packed", "__packed__":
				packed = true
			case "aligned", "__aligned__":
				if p.peek() == "(" {
					p.next()
					n, err := strconv.ParseInt(p.next(), 0, 32)
					if err != nil {
						return false, 0, errors.New("invalid aligned() value")
					}
					aligned = int(n)
					if err := p.expect(")"); err != nil {
						return false, 0, err
					}
				}
			}
		}
	}
	return packed, aligned, nil
}

func alignUp(n, a int) int { return (n + a - 1) / a * a }

func layout(k kind, fields []field, packed bool, aligned int) *ctype {
	t := &ctype{kind: k, fields: fields, align: 1}
	off := 0
	for i := range t.fields {
		f := &t.fields[i]
		a := f.t.align
		if packed {
			a = 1
		}
		t.align = max(t.align, a)
		if k == kUnion {
			f.off = 0
			off = max(off, f.t.size)
			continue
		}
		off = alignUp(off, a)
		f.off = off
		off += f.t.size
	}
	t.align = max(t.align, aligned)
	t.size = alignUp(off, t.align)
	return t
}

// --- formatting ---

func (t *ctype) uint(b []byte) uint64 {
	var v uint64
	switch t.size {
	case 1:
		v = uint64(b[0])
	case 2:
		if t.bigEndian {
			v = uint64(binary.BigEndian.Uint16(b))
		} else {
			v = uint64(binary.NativeEndian.Uint16(b))
		}
	case 4:
		if t.bigEndian {
			v = uint64(binary.BigEndian.Uint32(b))
		} else {
			v = uint64(binary.NativeEndian.Uint32(b))
		}
	case 8:
		if t.bigEndian {
			v = binary.BigEndian.Uint64(b)
		} else {
			v = binary.NativeEndian.Uint64(b)
		}
	}
	return v
}

func (t *ctype) putUint(b []byte, v uint64) {
	switch t.size {
	case 1:
		b[0] = byte(v)
	case 2:
		if t.bigEndian {
			binary.BigEndian.PutUint16(b, uint16(v))
		} else {
			binary.NativeEndian.PutUint16(b, uint16(v))
		}
	case 4:
		if t.bigEndian {
			binary.BigEndian.PutUint32(b, uint32(v))
		} else {
			binary.NativeEndian.PutUint32(b, uint32(v))
		}
	case 8:
		if t.bigEndian {
			binary.BigEndian.PutUint64(b, v)
		} else {
			binary.NativeEndian.PutUint64(b, v)
		}
	}
}

// format renders b (exactly t.size bytes) on one line. Top-level structs
// are rendered without braces: "a=1 b=2".
func (t *ctype) format(b []byte) string {
	if t.kind == kStruct || t.kind == kUnion {
		return strings.Join(t.fieldStrings(b), " ")
	}
	return t.formatValue(b)
}

func (t *ctype) fieldStrings(b []byte) []string {
	var out []string
	for _, f := range t.fields {
		fb := b[f.off:][:f.t.size]
		if f.name == "" { // anonymous member: inline its fields
			out = append(out, f.t.fieldStrings(fb)...)
			continue
		}
		out = append(out, f.name+"="+f.t.formatValue(fb))
	}
	return out
}

func (t *ctype) formatValue(b []byte) string {
	switch t.kind {
	case kInt:
		v := t.uint(b)
		switch {
		case t.hex:
			return fmt.Sprintf("0x%x", v)
		case t.char && v >= 0x20 && v < 0x7f:
			return strconv.QuoteRune(rune(v))
		case t.signed:
			shift := 64 - 8*t.size
			return strconv.FormatInt(int64(v<<shift)>>shift, 10)
		}
		return strconv.FormatUint(v, 10)
	case kBool:
		return strconv.FormatBool(b[0] != 0)
	case kFloat:
		if t.size == 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(binary.NativeEndian.Uint32(b))), 'g', -1, 32)
		}
		return strconv.FormatFloat(math.Float64frombits(binary.NativeEndian.Uint64(b)), 'g', -1, 64)
	case kPtr:
		return fmt.Sprintf("0x%x", binary.NativeEndian.Uint64(b))
	case kIP4, kIP6:
		return net.IP(b).String()
	case kMAC:
		return net.HardwareAddr(b).String()
	case kArray:
		e := t.elem
		if e.kind == kInt && e.char {
			s := b
			if i := strings.IndexByte(string(b), 0); i >= 0 {
				s = b[:i]
			}
			return strconv.Quote(string(s))
		}
		if e.kind == kInt && e.size == 1 && !e.signed {
			return "0x" + fmt.Sprintf("%x", b)
		}
		parts := make([]string, t.n)
		for i := range parts {
			parts[i] = e.formatValue(b[i*e.size:][:e.size])
		}
		return "[" + strings.Join(parts, " ") + "]"
	case kStruct, kUnion:
		return "{" + strings.Join(t.fieldStrings(b), " ") + "}"
	}
	return "?"
}

// lines renders one "path = value" line per leaf, for the detail view.
func (t *ctype) lines(prefix string, b []byte) []string {
	switch t.kind {
	case kStruct, kUnion:
		var out []string
		for _, f := range t.fields {
			p := prefix
			if f.name != "" {
				p = joinPath(prefix, f.name)
			}
			out = append(out, f.t.lines(p, b[f.off:][:f.t.size])...)
		}
		return out
	case kArray:
		e := t.elem
		if e.kind == kStruct || e.kind == kUnion || e.kind == kArray {
			var out []string
			for i := 0; i < t.n; i++ {
				out = append(out, e.lines(fmt.Sprintf("%s[%d]", prefix, i), b[i*e.size:][:e.size])...)
			}
			return out
		}
	}
	if prefix == "" {
		prefix = "value"
	}
	return []string{prefix + " = " + t.formatValue(b)}
}

// columns splits lines() into field names and values, for tables with one
// column per field (e.g. one row per CPU).
func (t *ctype) columns(b []byte) (names, values []string) {
	for _, l := range t.lines("", b) {
		name, val, _ := strings.Cut(l, " = ")
		names = append(names, name)
		values = append(values, val)
	}
	return names, values
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// sumPerCPU folds per-CPU copies into one value: integer fields (except
// chars and hex/flag fields) are summed, everything else is taken from CPU 0.
// This matches the usual "per-CPU counters struct" pattern.
func (t *ctype) sumPerCPU(vals [][]byte) []byte {
	out := append([]byte(nil), vals[0]...)
	t.walkInts(0, func(leaf *ctype, off int) {
		var sum uint64
		for _, v := range vals {
			sum += leaf.uint(v[off:][:leaf.size])
		}
		leaf.putUint(out[off:][:leaf.size], sum)
	})
	return out
}

func (t *ctype) walkInts(off int, fn func(*ctype, int)) {
	switch t.kind {
	case kInt:
		if !t.char && !t.hex {
			fn(t, off)
		}
	case kArray:
		for i := 0; i < t.n; i++ {
			t.elem.walkInts(off+i*t.elem.size, fn)
		}
	case kStruct:
		for _, f := range t.fields {
			f.t.walkInts(off+f.off, fn)
		}
	}
}

// --- persisted formats ---

type formatDef struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// formatStore holds the user's format definitions, keyed by map name (map
// IDs change every time a program is reloaded, names don't).
type formatStore struct {
	path string
	defs map[string]formatDef
	// embedded holds read-only defaults appended to the executable (see
	// readEmbeddedFormats); defs take precedence and are all that is saved.
	embedded map[string]formatDef
	// compiled caches parsed definitions; nil entries mean "not defined".
	compiled map[string]compiledFormat
}

type compiledFormat struct {
	key, value *ctype
}

func formatKey(mp mapRow) string {
	if mp.Name == "" {
		return fmt.Sprintf("id:%d", mp.ID)
	}
	return mp.Name
}

// configDir returns $XDG_CONFIG_HOME/ebpfexplorer. Under sudo, HOME and XDG vars
// usually point at root, so fall back to the invoking user's ~/.config to
// keep formats with the user who defined them.
func configDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "ebpfexplorer"), nil
	}
	if su := os.Getenv("SUDO_USER"); su != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(su); err == nil {
			return filepath.Join(u.HomeDir, ".config", "ebpfexplorer"), nil
		}
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "ebpfexplorer"), nil
}

// useGlobalConfig (--global-config) stores formats in the user's config
// directory instead of next to the binary.
var useGlobalConfig bool

// localFormatsFile is the formats file kept next to the binary by default.
const localFormatsFile = "ebpfexplorer-formats.json"

// formatsPath is where formats are loaded from and saved to.
func formatsPath() (string, error) {
	if useGlobalConfig {
		dir, err := configDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "formats.json"), nil
	}
	return localFormatsPath()
}

// localFormatsPath is next to the executable, symlinks resolved, so a
// symlinked or copied tool keeps its formats with the real binary.
func localFormatsPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), localFormatsFile), nil
}

func loadFormats(path string) (*formatStore, error) {
	s := &formatStore{path: path, defs: map[string]formatDef{}, compiled: map[string]compiledFormat{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	maps, err := parseFormatsJSON(data)
	if err != nil {
		return s, fmt.Errorf("%s: %w", s.path, err)
	}
	for name, d := range maps {
		s.defs[name] = d
		s.compiled[name] = compileDef(d)
	}
	return s, nil
}

func parseFormatsJSON(data []byte) (map[string]formatDef, error) {
	var file struct {
		Maps map[string]formatDef `json:"maps"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Maps, nil
}

// compileDef parses a stored definition. Definitions were validated when
// saved; a hand-edited broken one simply shows as hex.
func compileDef(d formatDef) compiledFormat {
	var c compiledFormat
	c.key, _ = parseOptional(d.Key)
	c.value, _ = parseOptional(d.Value)
	return c
}

// setEmbedded installs read-only default formats; maps that already have a
// user definition keep it.
func (s *formatStore) setEmbedded(defs map[string]formatDef) {
	s.embedded = defs
	for name, d := range defs {
		if _, ok := s.defs[name]; !ok {
			s.compiled[name] = compileDef(d)
		}
	}
}

// Formats can be appended to the executable so a single file carries them:
//
//	<binary><formats JSON><JSON length, 16 decimal digits>EBPFXCFG
//
// The kernel ignores bytes past the ELF segments, so the binary still runs.
const (
	embeddedMagic      = "EBPFXCFG"
	embeddedTrailerLen = 16 + len(embeddedMagic)
)

// readEmbeddedFormats returns the formats appended to the executable at
// path, or nil if there are none.
func readEmbeddedFormats(path string) (map[string]formatDef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < int64(embeddedTrailerLen) {
		return nil, nil
	}
	trailer := make([]byte, embeddedTrailerLen)
	if _, err := f.ReadAt(trailer, st.Size()-int64(embeddedTrailerLen)); err != nil {
		return nil, err
	}
	if string(trailer[16:]) != embeddedMagic {
		return nil, nil
	}
	n, err := strconv.ParseInt(string(trailer[:16]), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("embedded formats: bad length %q", trailer[:16])
	}
	if n < 0 || n > st.Size()-int64(embeddedTrailerLen) {
		return nil, fmt.Errorf("embedded formats: length %d out of range", n)
	}
	data := make([]byte, n)
	if _, err := f.ReadAt(data, st.Size()-int64(embeddedTrailerLen)-n); err != nil {
		return nil, err
	}
	maps, err := parseFormatsJSON(data)
	if err != nil {
		return nil, fmt.Errorf("embedded formats: %w", err)
	}
	return maps, nil
}

func parseOptional(src string) (*ctype, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	return parseCType(src)
}

func (s *formatStore) get(mp mapRow) compiledFormat {
	return s.compiled[formatKey(mp)]
}

// def is the definition in effect for mp: the user's, else the embedded one.
func (s *formatStore) def(mp mapRow) formatDef {
	name := formatKey(mp)
	if d, ok := s.defs[name]; ok {
		return d
	}
	return s.embedded[name]
}

func (s *formatStore) set(mp mapRow, d formatDef, c compiledFormat) error {
	name := formatKey(mp)
	if d.Key == "" && d.Value == "" {
		delete(s.defs, name)
		if e, ok := s.embedded[name]; ok {
			s.compiled[name] = compileDef(e)
		} else {
			delete(s.compiled, name)
		}
	} else {
		s.defs[name] = d
		s.compiled[name] = c
	}
	return s.save()
}

func (s *formatStore) save() error {
	if s.path == "" {
		return errors.New("no config directory available")
	}
	data, err := json.MarshalIndent(struct {
		Maps map[string]formatDef `json:"maps"`
	}{s.defs}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	// Remember which directories we create (e.g. a missing ~/.config) so
	// they can be handed back to the sudo user too.
	var created []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil || d == filepath.Dir(d) {
			break
		}
		created = append(created, d)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	chownToSudoUser(append(created, s.path)...)
	return nil
}

// chownToSudoUser hands files created while running under sudo back to the
// invoking user, so their config doesn't end up owned by root.
func chownToSudoUser(paths ...string) {
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || os.Geteuid() != 0 {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}
