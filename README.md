# ebpfexplorer

Terminal UI to explore eBPF programs, attached maps and map entries loaded on your machine.

```sh
go build -o ebpfexplorer ./cmd/ebpfexplorer
sudo ./ebpfexplorer
```

or

```sh
go install github.com/noboruma/ebpfexplorer/cmd/ebpfexplorer@latest
```

or

```sh
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL -o ebpfexplorer "https://github.com/noboruma/ebpfexplorer/releases/latest/download/ebpfexplorer-linux-${arch}"
chmod +x ebpfexplorer
sudo ./ebpfexplorer
```

or download the binaries in the Github release section.

Same keys on every screen: `[↑/↓]` move, `[←/→]` scroll sideways to read anything cut off with `…`
(columns and header lines; `←` at the left edge goes back), `[enter]` open, `[esc]` back.

To ship a config within your binary, see below.

## Programs Explorer (Root View)

Shows every loaded BPF program, the CPU it uses and where it is attached. `[/]` filters on name, `[m]` switches
to the [list of all maps](#all-maps), `[d]` shows the program's [code](#code-explorer).

```
 eBPF explorer  programs
 ID      Name                 Type           CPU%    Maps  Attached
───────────────────────────────────────────────────────────────────────────────────────
 41      xdp_proxy_filter     XDP            3.42    2     xdp@eth0 (native)
 42      tc_bandwidth         SchedCLS       0.87    1     tcx@eth0
 57      trace_connect        Kprobe         <0.01   1
 10122   sd_devices           CGroupDevice   0       0     cgroup/device@systemd-udevd.service
4 programs
[↑/↓] move  [←/→] scroll  [enter] open  [d] code  [/] filter  [m] all maps  [r] refresh programs  [q] quit
```

`CPU%` is the time the program ran over the last 2 seconds, as in `top`: 100% is one CPU fully busy, and a program
running on several CPUs can go above. The program's maps screen shows it in its header too. The kernel only counts
run time while BPF statistics are on: the explorer turns them on while it runs (`BPF_ENABLE_STATS`, Linux 5.8+),
which adds a clock read to every program run, and the kernel turns them off again when it quits, unless
`sysctl kernel.bpf_stats_enabled=1` keeps them on. Without them (older kernel, missing `CAP_SYS_ADMIN`), the column
shows `-` and the status line says why.

## Code Explorer

`[d]` on a program (or on its maps screen) shows its instructions as the kernel runs them, after the
verifier rewrote them, in bpftool's C-like syntax. Each instruction sits next to the C line it was compiled
from: clang `-g` ships the source lines inside the program's BTF, so no source file is needed. `[enter]` on a
jump or a bpf-to-bpf call goes to its target.

```
 eBPF explorer  programs
prog 41 count_packets  XDP  tag a1b2c3d4e5f60718
25 instructions (xlated)  •  JIT 151 bytes  •  C source from BTF line info
 #      Bytes                    Instruction                                  C source
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
                                 count_packets:
 0      61 12 00 00 00 00 00 00  r2 = *(u32 *)(r1 +0)                         prog.c:30  __u32 key = bucket(ctx->d…
 1      61 11 04 00 00 00 00 00  r1 = *(u32 *)(r1 +4)
 2      1c 21 00 00 00 00 00 00  w1 -= w2
 3      85 10 00 00 ff ff ff ff  call bucket
 9      18 11 00 00 00 00 00 0…  r1 = counts
 11     85 00 00 00 01 00 00 00  call bpf_map_lookup_elem
 12     15 00 02 00 00 00 00 00  if r0 == 0x0 goto pc+2                       prog.c:32  if (n) {
 13     db 60 00 00 01 00 00 00  r6 = atomic64_fetch_add((u64 *)(r0 +0), r6)  prog.c:33  __sync_fetch_and_add(n, 1);
row 12/28 • jumps to 15 [enter]
[↑/↓ pgup/pgdn g/G] move  [←/→] scroll  [enter] follow jump/call  [esc] back  [r] reload  [q] quit
```

Reading instructions needs root; the C column stays empty for programs built without `-g`.

## Maps Explorer

After selecting a program, `ebpfexplorer` shows the maps a program uses, with their entry count (counted in the background) and whether a format is defined.
The header shows where the program is attached, its CPU usage, which processes hold it open, and its tag: the
kernel's hash of its instructions (as `bpftool` shows it), the same for every program loaded from the same code.

```
 eBPF explorer  programs › prog 41 xdp_proxy_filter
attached: xdp@eth0 (native)  •  cpu: 3.42%  •  processes: proxy-agent (pid 2211)  •  tag: a1b2c3d4e5f60718
 ID      Name                Type            Key   Value  MaxEntries  Entries     Flags  Format
─────────────────────────────────────────────────────────────────────────────────────────────────
 12      flows               PerCPUHash      12    16     10000000    counting…   0x0    key+val
 13      blocklist           LPMTrie         8     4      65536       1532        0x0
[↑/↓] move  [←/→] scroll  [enter] open  [/] filter  [e] edit format  [esc] back  [r] refresh maps  [q] quit
```

## All Maps

`[m]` (or `sudo ./ebpfexplorer -maps` to start there) lists every map loaded in the kernel, including maps
no program uses, such as maps only held open or pinned by a process. Entries open from it the same way;
`[esc]` from the entries comes back here, and `[p]` returns to the programs.

```
 eBPF explorer  all maps
 ID      Name                Type            Key   Value  MaxEntries  Entries     Flags  Format
─────────────────────────────────────────────────────────────────────────────────────────────────
 12      flows               PerCPUHash      12    16     10000000    counting…   0x0    key+val
 13      blocklist           LPMTrie         8     4      65536       1532        0x0
 30      int_2_id            Hash            4     4      1024        87          0x0
3 maps
[↑/↓] move  [←/→] scroll  [enter] open  [/] filter  [e] edit format  [p] programs  [r] refresh maps  [q] quit
```

## Entries Explorer

After selecting a map, `ebpfexplorer` shows all entries of a map. Entries are streamed in chunks of 1000 so big maps are usable right away.
Per-CPU values are summed across CPUs (`Σ 42` for a number, `{a=1 b=2}` for a struct). The header lists every program using the map and every process holding it open.

```
 eBPF explorer  programs › prog 41 xdp_proxy_filter › map 12 flows
type=PerCPUHash key=12B value=16B max_entries=10000000
programs: xdp_proxy_filter (41), tc_bandwidth (42)
processes: proxy-agent (pid 2211)
 #         Key                                         Value
──────────────────────────────────────────────────────────────────────────────────────────────────
 0         saddr=10.0.0.1 sport=443 proto=6 ifindex=2  {packets=12 bytes=1600}
 1         saddr=10.0.0.2 sport=443 proto=6 ifindex=2  {packets=22 bytes=3100}
 2         saddr=10.0.0.3 sport=443 proto=6 ifindex=2  {packets=32 bytes=4600}
loading entries… 3 / ~2400000 (0%) • row 1/3 • [FORMAT]
[↑/↓ pgup/pgdn g/G] move  [←/→] scroll  [enter] open  [/] search  [w] write  [e] edit format  [esc] back  [r] refresh map  [q] quit
```

Without a format (`[e]` to define one), keys and values are shown in hex format:

```
 #         Key (hex)              Key           Value (hex)                      Value
────────────────────────────────────────────────────────────────────────────────────────────────
 0         0a 00 00 01 01 bb 06…                [2 CPUs] 05 00 00 00 00 00 00 …
 1         0a 00 00 02 01 bb 06…                [2 CPUs] 0f 00 00 00 00 00 00 …
 2         0a 00 00 03 01 bb 06…                [2 CPUs] 19 00 00 00 00 00 00 …
loading entries… 3 / ~2400000 (0%) • row 1/3 • [HEX: no format, press e]
```

## Entry Explorer

After selecting an entry, `ebpfexplorer` shows it, field by field (or as a hex dump if there is no defined format).
For per-CPU maps it shows a table instead: one row per CPU, one column per field, and the sum (`Σ`) on top.

```
 eBPF explorer  programs › prog 41 xdp_proxy_filter › map 12 flows › entry
map 12 "flows" (PerCPUHash)  entry #0
key: saddr=10.0.0.1 sport=443 proto=6 ifindex=2
 CPU   packets                                       bytes
──────────────────────────────────────────────────────────────────────────────────────────────────
 Σ     12                                            1600
 0     5                                             900
 1     7                                             700
[FORMAT]
[↑/↓] move  [←/→] scroll  [w] write CPU  [e] edit format  [esc] back  [r] refresh entry  [q] quit
```

## Writing an Entry

Writing is off by default: start with `sudo ./ebpfexplorer --allow-write` (or `-w`) to enable it (it also enables
[pausing programs](#pausing-a-program)). Then `[w]` on an
entry (in the entries list or the entry itself) opens its value for writing: one input per
field of the value's format, or the value's hex without one. Only the fields you change are written; the
rest of the value keeps the bytes read. `[enter]` checks the fields, then asks before writing; the entry is
read back from the kernel once written. The key must still exist: a deleted entry is not created again.

```
Write map 12 "flows" entry #0 on all 2 CPUs
key: 0a 00 00 01 01 bb 06 00 02 00 00 00

›  packets u64   differs per CPU: empty keeps each CPU's value
   bytes u64     0

write 1 changed field(s) to the map on all 2 CPUs? [y] write  [any key] back
```

Fields take what the screen shows: numbers (`42`, `0x2a`, `-3`), `10.0.0.1`, `fe80::1`,
`aa:bb:cc:dd:ee:ff`, `"eth0"` for `char[]`, `0xdeadbeef` for `__u8[]`, `[1 2 3]` for other arrays.
Per-CPU maps are written on every CPU from the entries list, or on one CPU with `[w]` on its row of the
entry's CPU table (`Σ` writes them all). Values that are file descriptors (program arrays, maps of maps,
sockmaps) can't be written.

## Pausing a Program

With `--allow-write` (`-w`), `[D]` on a program (in the programs list or on its maps screen) pauses it, after a
`[y]` to confirm; `[D]` again resumes it. The kernel can't pause a program, so each of its XDP, tcx, netkit and
cgroup bpf_links is pointed at a do-nothing program instead (`BPF_LINK_UPDATE`): XDP passes packets, tcx and
netkit move on to the next program, cgroup hooks allow. The link and the process that owns it don't change, and
the loader sees nothing unusual.

```
 41      xdp_proxy_filter     XDP            0       2     xdp@eth0 (paused)
 98      ebpfx_paused         XDP            <0.01   0     xdp@eth0
```

The do-nothing program is listed as `ebpfx_paused`; `[D]` on it resumes too. Other attachments (kprobes, fentry,
tracepoints, legacy cgroup or netlink XDP attachments) are left alone. While paused, the explorer is what keeps
the original program loaded: **quitting resumes every paused program**. If the explorer is killed (`SIGKILL`)
while a program is paused, the do-nothing program stays attached, and the original is unloaded unless its owner
still holds it.

## Keybind: Key Search

`[/]` searches keys as hex (`0a000002`, `0a 00 00 02`), decimal, IP, or formatted fields (`sport=443`).

```
type=PerCPUHash key=12B value=16B max_entries=10000000
/10.0.0.2
 #         Key                                         Value
──────────────────────────────────────────────────────────────────────────────────────────────────
 1         saddr=10.0.0.2 sport=443 proto=6 ifindex=2  {packets=22 bytes=3100}
loading entries… 3 / ~2400000 (0%) • 1 match • row 1/1 • [FORMAT]
```

## Keybind: Formats

`[e]` allows you to define C structs for a map's key and/or value. They are checked against the map's
sizes and saved by map name, so they apply again after the program is reloaded (see [Format storage](#format-storage)).
`[↑/↓]` move through Key, Value and the [link](#keybind-links) fields. `[esc]` always saves and goes back: to undo a
change, clear the field (empty = hex) or pick `(no link)`. A definition with an error keeps the one saved before (and
a link that doesn't fit is dropped); the status line says what wasn't saved.

```
╭──────────────────────────────────────────────────────────────────────────────────────────────╮
│ Format for map 12 "flows" (key 12B, value 16B)                                               │
│ saved by map name in /usr/local/bin/ebpfexplorer-formats.json                                │
│                                                                                              │
│ ▸ Key                                                                                        │
│   struct { ipv4 saddr; __be16 sport; __u8 proto; __u32 ifindex; }                            │
│   ✓ 12 bytes                                                                                 │
│                                                                                              │
│   Value                                                                                      │
│   struct { __u64 packets; }                                                                  │
│   ✗ definition is 8 bytes but the map's value is 16 bytes                                    │
│                                                                                              │
│ types:  char short int long unsigned…  __u8…__u64 __s8…__s64 uint8_t…  __be16/32/64  bool    │
│ float double                                                                                 │
│ extras: ipv4 ipv6 mac, x8…x64 (hex); arrays a[N], nested struct/union, pointers              │
│ attrs:  __attribute__((packed)), __attribute__((aligned(N)))                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
[↑/↓] move  [esc] save & back
```

Note that IPs are correctly formatted as human readable: `1.2.3.4`

## Keybind: Links

Links translate IDs: a field of the format is looked up as a key in another map, and the value found there is shown
in place, right after the field. For example, a `flows` map holding a `backend_id` linked to a `backends` map
(`backend_id → ip, port`) shows each flow's backend address.

Links are part of the format editor (`[e]`): below Key and Value, it lists every field of the key and value formats,
plus the whole key and value. Fields follow the formats as you type them. `[↓]` down to a field and `[enter]` opens a
popup listing every loaded map; type to filter, `[enter]` to link. Maps whose key size doesn't fit the field are
greyed out and refused; a smaller host-order integer is widened to the map's key size (a `__u16` id can look up a
`__u32` key). `[backspace]` removes a link, and `[esc]` saves the format and its links together.

```
╭──────────────────────────────────────────────────────────────────────────────────────────────╮
│ Format for map 12 "flows" (key 8B, value 16B)                                                │
│ s╭────────────────────────────────────────────────────────────────────────────────────────╮  │
│  │ Link key.backend_id (4B) to                                                            │  │
│  │ /back                                                                                  │  │
│  │ (no link)                                                                              │  │
│  │ backends             14  Hash         key   4B  value    8B •                          │  │
│  │ backends_v6          31  Hash         key   4B  value   20B                            │  │
│  │ 2 maps • used by this program • greyed: key size doesn't fit                           │  │
│  ╰────────────────────────────────────────────────────────────────────────────────────────╯  │
│   ✓ 16 bytes                                                                                 │
│                                                                                              │
│ ▸ Links  a linked field is looked up as a key in that map and the value found there is shown │
│     Field            Size  Linked map                                                        │
│     key                8B                                                                    │
│   ▸ key.backend_id     4B  backends ✓                                                        │
│     key.port           4B                                                                    │
│     value             16B                                                                    │
│     value.packets      8B                                                                    │
│     value.bytes        8B                                                                    │
│   ✓ map 14 "backends": key 4B, value 8B                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
[↑/↓] move  [type] filter  [enter] link  [esc] close
```

Each linked field is then followed by its translation, formatted with the linked map's own format, in the Key or
Value column (titled `Key (linked)` / `Value (linked)`) and in the entry view. `[/]` search matches the key's translations
too, so `/10.0.0.5` finds the flows going to that backend:

```
 #         Key (linked)                                     Value
──────────────────────────────────────────────────────────────────────────────────────────────────
 0         backend_id=3→{ip=10.0.0.5 port=80} port=443      {packets=12 bytes=1600}
 1         backend_id=9→(not found) port=80                 {packets=22 bytes=3100}
```

Links are saved with the format, in the same entry as its key and value (the `links` field, see
[Format storage](#format-storage)), by map name on both ends, so
[bundling the formats into the binary](#formats-bundled-in-the-binary) carries the links too. When several loaded
maps share the linked name, the one used by the current program wins (`•` in the popup), else the most recently
loaded. Value fields of per-CPU maps are looked up from CPU 0's copy. `[r]` reads the linked maps again.

## Format storage

By default, formats are loaded from and saved to `ebpfexplorer-formats.json`, **next to the `ebpfexplorer` binary**
(symlinks are followed). Keep the binary and its formats together, e.g. in a project folder or a repository,
to share them with the team.

`--global-config` uses your user config directory instead: `$XDG_CONFIG_HOME/ebpfexplorer/formats.json`
(`~/.config/ebpfexplorer/formats.json` by default; under `sudo`, the config of the user who ran `sudo`).

```sh
sudo ./ebpfexplorer                  # ./ebpfexplorer-formats.json
sudo ./ebpfexplorer --global-config  # ~/.config/ebpfexplorer/formats.json
```

Files created under `sudo` are given back to the user who ran it. The format editor shows the file in use.
Both files have the same layout, keyed by map name:

```json
{
  "maps": {
    "flows": {
      "key": "struct { ipv4 saddr; __be16 sport; __u8 proto; __u32 ifindex; }",
      "value": "struct { __u64 packets; __u64 bytes; }",
      "links": { "key.saddr": "hosts" }
    }
  }
}
```

### Formats bundled in the binary

A formats file can also be appended to the binary, so a single file carries them. Bundled formats are
read-only defaults: a format saved with `[e]` takes precedence (and is saved to the file above, never to
the binary), and clearing it falls back to the bundled one. Run the following to bundle `formats.json` into
`ebpfexplorer`, replacing any formats already bundled:

```sh
# layout: <binary><formats JSON><JSON length, 16 digits>EBPFXCFG
if [ "$(tail -c 8 ebpfexplorer | tr -d '\0')" = EBPFXCFG ]; then
  head -c -$(expr $(tail -c 24 ebpfexplorer | head -c 16) + 24) ebpfexplorer > ebpfexplorer.tmp && mv ebpfexplorer.tmp ebpfexplorer
fi
cat formats.json >> ebpfexplorer
printf '%016d%s' $(stat -c %s formats.json) EBPFXCFG >> ebpfexplorer
chmod +x ebpfexplorer
```

In a Makefile recipe, write each `$` as `$$`. Tools that rewrite the ELF, such as `strip` or `upx`, drop the
bundled formats.

## Keybind: Refresh

`[r]` refreshes only what you are looking at: the program list, the program's maps, the whole map, or a single entry.
