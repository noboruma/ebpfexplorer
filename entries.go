package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
)

const chunkSize = 1000

// chunk holds up to chunkSize entries in two flat buffers, so millions of
// entries cost little more than their raw bytes:
//
//	key i         = keys[i*keySize:][:keySize]
//	value i, cpu c = vals[(i*ncpu+c)*valSize:][:valSize]
type chunk struct {
	n    int
	keys []byte
	vals []byte
}

// entryStore is the append-only set of chunks read so far. Chunks are never
// mutated once appended, so a copy of the slice can be scanned concurrently.
type entryStore struct {
	keySize, valSize, ncpu int
	chunks                 []*chunk
	starts                 []int // global index of each chunk's first entry
	total                  int
}

func (s *entryStore) append(c *chunk) {
	s.chunks = append(s.chunks, c)
	s.starts = append(s.starts, s.total)
	s.total += c.n
}

func (s *entryStore) locate(i int) (*chunk, int) {
	ci := sort.Search(len(s.starts), func(j int) bool { return s.starts[j] > i }) - 1
	return s.chunks[ci], i - s.starts[ci]
}

func (s *entryStore) key(i int) []byte {
	c, j := s.locate(i)
	return c.keys[j*s.keySize:][:s.keySize]
}

// values returns one slice per CPU (a single slice for regular maps).
func (s *entryStore) values(i int) [][]byte {
	c, j := s.locate(i)
	out := make([][]byte, s.ncpu)
	for cpu := range out {
		out[cpu] = c.vals[(j*s.ncpu+cpu)*s.valSize:][:s.valSize]
	}
	return out
}

// setValues overwrites entry i's values in place after a refresh. Keys are
// never touched, so this doesn't race with background key searches.
func (s *entryStore) setValues(i int, vals [][]byte) {
	c, j := s.locate(i)
	for cpu := 0; cpu < s.ncpu && cpu < len(vals); cpu++ {
		copy(c.vals[(j*s.ncpu+cpu)*s.valSize:][:s.valSize], vals[cpu])
	}
}

// entryLoader streams a map's contents chunk by chunk. It prefers
// BPF_MAP_LOOKUP_BATCH (one syscall per chunk) and falls back to
// NextKey+Lookup for map types or kernels without batch support.
type entryLoader struct {
	m                      *ebpf.Map
	keySize, valSize, ncpu int
	perCPU                 bool

	useBatch bool
	cursor   ebpf.MapBatchCursor
	lastKey  []byte // resume point for the NextKey fallback
	done     bool
}

func openLoader(id ebpf.MapID) (*entryLoader, error) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return nil, err
	}
	switch m.Type() {
	case ebpf.PerfEventArray, ebpf.RingBuf, ebpf.UserRingbuf:
		m.Close()
		return nil, fmt.Errorf("%s maps are event streams and cannot be iterated", m.Type())
	}
	l := &entryLoader{
		m:        m,
		keySize:  int(m.KeySize()),
		valSize:  int(m.ValueSize()),
		ncpu:     1,
		perCPU:   isPerCPU(m.Type()),
		useBatch: true,
	}
	if l.perCPU {
		if l.ncpu, err = ebpf.PossibleCPU(); err != nil {
			m.Close()
			return nil, err
		}
	}
	return l, nil
}

func (l *entryLoader) Close() { l.m.Close() }

// next reads the next chunk. It may return fewer than chunkSize entries; the
// loader is exhausted once l.done is set.
func (l *entryLoader) next() (*chunk, error) {
	if l.useBatch {
		c, err := l.nextBatch()
		if err == nil {
			return c, nil
		}
		// Not supported for this map type/kernel, or a hash bucket larger than
		// the chunk (ENOSPC): continue key by key from where we stopped.
		l.useBatch = false
	}
	return l.nextIter()
}

func (l *entryLoader) nextBatch() (*chunk, error) {
	keys, keyBuf := byteArraySlice(l.keySize, chunkSize)
	vals, valBuf := byteArraySlice(l.valSize, chunkSize*l.ncpu)
	n, err := l.m.BatchLookup(&l.cursor, keys.Interface(), vals.Interface(), nil)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		l.done = true
	} else if err != nil {
		return nil, err
	}
	c := &chunk{n: n, keys: keyBuf[:n*l.keySize], vals: valBuf[:n*l.ncpu*l.valSize]}
	if n > 0 {
		l.lastKey = c.keys[(n-1)*l.keySize:]
	}
	return c, nil
}

func (l *entryLoader) nextIter() (*chunk, error) {
	c := &chunk{
		keys: make([]byte, 0, chunkSize*l.keySize),
		vals: make([]byte, 0, chunkSize*l.ncpu*l.valSize),
	}
	var prev any
	if l.lastKey != nil {
		prev = l.lastKey
	}
	for c.n < chunkSize {
		key, err := l.m.NextKeyBytes(prev)
		if err != nil {
			return c, err
		}
		if key == nil {
			l.done = true
			break
		}
		prev, l.lastKey = key, key

		if l.perCPU {
			var vals [][]byte
			if err := l.m.Lookup(key, &vals); err != nil {
				continue // deleted since NextKey
			}
			c.keys = append(c.keys, key...)
			for _, v := range vals {
				c.vals = append(c.vals, v...)
			}
		} else {
			val, err := l.m.LookupBytes(key)
			if err != nil || val == nil {
				continue
			}
			c.keys = append(c.keys, key...)
			c.vals = append(c.vals, val...)
		}
		c.n++
	}
	return c, nil
}

// byteArraySlice makes a []([size]byte) of length n, which the batch API
// needs to infer element sizes, and returns its backing memory as flat bytes.
func byteArraySlice(size, n int) (reflect.Value, []byte) {
	v := reflect.MakeSlice(reflect.SliceOf(reflect.ArrayOf(size, reflect.TypeFor[byte]())), n, n)
	if size == 0 || n == 0 {
		return v, nil
	}
	return v, unsafe.Slice((*byte)(v.UnsafePointer()), size*n)
}

// --- key search ---

type keyQuery struct {
	raw, hex string
	format   *ctype // when set, the formatted key is searched too
}

func newKeyQuery(s string) keyQuery {
	q := strings.ToLower(strings.TrimSpace(s))
	return keyQuery{raw: q, hex: strings.ReplaceAll(q, " ", "")}
}

func (q keyQuery) empty() bool { return q.raw == "" }

// match accepts the key's hex (with or without spaces) or its decoded form,
// so "0a000001", "0a 00 00 01", "10.0.0.1" and "16777226" find the same key.
func (q keyQuery) match(key []byte) bool {
	if strings.Contains(hex.EncodeToString(key), q.hex) || strings.Contains(decode(key), q.raw) {
		return true
	}
	return q.format != nil && strings.Contains(strings.ToLower(q.format.format(key)), q.raw)
}

// filterChunks returns the global indices of matching keys in chunks[from:].
// It gives up (returning ok=false) as soon as *gen no longer equals want,
// meaning a newer search superseded this one.
func filterChunks(s entryStore, from int, q keyQuery, gen *atomic.Int64, want int64) (idx []int32, ok bool) {
	for ci := from; ci < len(s.chunks); ci++ {
		if gen != nil && gen.Load() != want {
			return nil, false
		}
		c := s.chunks[ci]
		for j := 0; j < c.n; j++ {
			if q.match(c.keys[j*s.keySize:][:s.keySize]) {
				idx = append(idx, int32(s.starts[ci]+j))
			}
		}
	}
	return idx, true
}
