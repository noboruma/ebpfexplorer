package internal

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func cat(parts ...[]byte) []byte { return slices.Concat(parts...) }

func TestFormat(t *testing.T) {
	neg := int32(-5)
	for _, tc := range []struct {
		def  string
		size int
		data []byte
		want string
	}{
		{"struct {int a; int b;}", 8, cat(le32(1), le32(2)), "a=1 b=2"},
		{"int a; int b;", 8, cat(le32(1), le32(uint32(neg))), "a=1 b=-5"},
		{"__u64", 8, le64(1 << 40), "1099511627776"},
		{"ipv4 saddr", 4, []byte{10, 0, 0, 1}, "saddr=10.0.0.1"},
		{"ipv4 saddr;", 4, []byte{10, 0, 0, 1}, "saddr=10.0.0.1"},
		{"ipv4", 4, []byte{10, 0, 0, 1}, "10.0.0.1"},
		{"__u8 addr[4]", 4, []byte{10, 0, 0, 1}, "addr=0x0a000001"},
		{"unsigned long long int", 8, le64(7), "7"},
		{"short", 2, le16(0xffff), "-1"},
		// Natural alignment: u8 at 0, padding, u32 at 4, u16 at 8, size 12.
		{"struct { __u8 p; __u32 ip; __u16 port; }", 12,
			cat([]byte{6, 0, 0, 0}, le32(9), le16(80), []byte{0, 0}), "p=6 ip=9 port=80"},
		{"struct { __u8 p; __u32 ip; } __attribute__((packed))", 5,
			cat([]byte{17}, le32(9)), "p=17 ip=9"},
		{"struct { ipv4 saddr; __be16 sport; mac src; }", 12,
			cat([]byte{10, 0, 0, 1}, []byte{0x1f, 0x90}, []byte{0xaa, 0xbb, 0xcc, 0, 1, 2}),
			"saddr=10.0.0.1 sport=8080 src=aa:bb:cc:00:01:02"},
		{"struct { char comm[8]; __u32 pid; }", 12,
			cat([]byte("curl\x00\x00\x00\x00"), le32(42)), `comm="curl" pid=42`},
		{"struct { __u32 v[3]; x32 flags; }", 16,
			cat(le32(1), le32(2), le32(3), le32(0xff)), "v=[1 2 3] flags=0xff"},
		{"struct { __u32 a; struct { __u16 x; __u16 y; } pt; }", 8,
			cat(le32(1), le16(2), le16(3)), "a=1 pt={x=2 y=3}"},
		{"struct { __u32 a; union { __u32 u; __u8 b[4]; }; }", 8,
			cat(le32(1), []byte{1, 2, 3, 4}), "a=1 u=67305985 b=0x01020304"},
		{"struct { __u8 a; __u64 b __attribute__((aligned(16))); }", 32,
			make([]byte, 32), "a=0 b=0"},
		{"struct key { __u32 ip; /* addr */ __u32 port; // trailing\n } k;", 8,
			cat(le32(1), le32(2)), "ip=1 port=2"},
	} {
		ct, err := parseCType(tc.def)
		if err != nil {
			t.Errorf("%q: %v", tc.def, err)
			continue
		}
		if ct.size != tc.size {
			t.Errorf("%q: size %d, want %d", tc.def, ct.size, tc.size)
			continue
		}
		if got := ct.format(tc.data); got != tc.want {
			t.Errorf("%q:\n got  %s\n want %s", tc.def, got, tc.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, def := range []string{
		"",
		"struct { int a }",
		"struct foo",
		"struct { int a : 3; }",
		"struct { wat a; }",
		"struct {}",
		"int a; int",
	} {
		if _, err := parseCType(def); err == nil {
			t.Errorf("%q: expected an error", def)
		}
	}
}

func TestLines(t *testing.T) {
	ct, err := parseCType("struct { __u32 a; struct { __u16 x; } pt[2]; }")
	if err != nil {
		t.Fatal(err)
	}
	got := ct.lines("", cat(le32(1), le16(2), le16(3)))
	want := []string{"a = 1", "pt[0].x = 2", "pt[1].x = 3"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSumPerCPU(t *testing.T) {
	ct, err := parseCType("struct { __u64 packets; __u64 bytes; x32 flags; ipv4 last; }")
	if err != nil {
		t.Fatal(err)
	}
	cpu0 := cat(le64(1), le64(100), le32(0xf), []byte{10, 0, 0, 1})
	cpu1 := cat(le64(2), le64(200), le32(0x1), []byte{10, 0, 0, 2})
	got := ct.format(ct.sumPerCPU([][]byte{cpu0, cpu1}))
	if want := "packets=3 bytes=300 flags=0xf last=10.0.0.1"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestFormatStorePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), LocalFormatsFile)
	s, err := loadFormats(path)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := parseCType("__u32")
	mp := mapRow{ID: 7, Name: "conntrack"}
	if err := s.set(mp, formatDef{Key: "__u32"}, compiledFormat{key: k}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"conntrack"`) {
		t.Fatalf("%s = %s, %v", path, data, err)
	}

	// A new ID for the same map name (program reloaded) finds the format.
	s2, err := loadFormats(path)
	if err != nil {
		t.Fatal(err)
	}
	if c := s2.get(mapRow{ID: 99, Name: "conntrack"}); c.key == nil || c.key.size != 4 {
		t.Fatalf("format not reloaded: %+v", c)
	}
}

func TestFormatsPath(t *testing.T) {
	defer func(v bool) { useGlobalConfig = v }(useGlobalConfig)
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}

	// Default: next to the binary.
	useGlobalConfig = false
	if got, err := formatsPath(); err != nil || got != filepath.Join(filepath.Dir(exe), "ebpfexplorer-formats.json") {
		t.Fatalf("local path = %q, %v", got, err)
	}

	// --global-config: $XDG_CONFIG_HOME/ebpfexplorer/formats.json.
	useGlobalConfig = true
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got, err := formatsPath(); err != nil || got != "/xdg/ebpfexplorer/formats.json" {
		t.Fatalf("global path = %q, %v", got, err)
	}
}

func TestEmbeddedFormats(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "ebpfexplorer")

	// No trailer: nothing embedded.
	if err := os.WriteFile(exe, []byte("\x7fELF...binary..."), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := readEmbeddedFormats(exe); err != nil || got != nil {
		t.Fatalf("plain binary: %v, %v", got, err)
	}

	// Same layout the README's shell commands produce.
	js := `{"maps": {"conntrack": {"key": "__u32"}, "flows": {"value": "__u64", "links": {"value": "names"}}}}` + "\n"
	f, _ := os.OpenFile(exe, os.O_APPEND|os.O_WRONLY, 0)
	fmt.Fprintf(f, "%s%016d%s", js, len(js), embeddedMagic)
	f.Close()
	got, err := readEmbeddedFormats(exe)
	if err != nil || got["conntrack"].Key != "__u32" || got["flows"].Value != "__u64" || got["flows"].Links["value"] != "names" {
		t.Fatalf("embedded: %v, %v", got, err)
	}

	// User definitions win; clearing one falls back to the embedded default,
	// and embedded defaults are never written to the user's file.
	path := filepath.Join(dir, LocalFormatsFile)
	s, _ := loadFormats(path)
	s.setEmbedded(got)
	if l := s.def(mapRow{Name: "flows"}).Links; l["value"] != "names" {
		t.Fatalf("embedded links not applied: %v", l)
	}
	mp := mapRow{Name: "conntrack"}
	if c := s.get(mp); c.key == nil || c.key.size != 4 {
		t.Fatalf("embedded format not applied: %+v", c)
	}
	k, _ := parseCType("__u64")
	if err := s.set(mp, formatDef{Key: "__u64"}, compiledFormat{key: k}); err != nil {
		t.Fatal(err)
	}
	if c := s.get(mp); c.key.size != 8 || s.def(mp).Key != "__u64" {
		t.Fatalf("user format not preferred: %+v", c)
	}
	if err := s.set(mp, formatDef{}, compiledFormat{}); err != nil {
		t.Fatal(err)
	}
	if c := s.get(mp); c.key == nil || c.key.size != 4 {
		t.Fatalf("embedded format not restored: %+v", c)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "flows") {
		t.Fatalf("embedded formats saved to user file: %s", data)
	}
}
