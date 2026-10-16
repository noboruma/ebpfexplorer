# ebpfexplorer

Terminal UI to explore eBPF programs, attached maps and map entries loaded on your machine.

```sh
go build -o ebpfexplorer .
sudo ./ebpfexplorer
```

or

```sh
go install github.com/noboruma/ebpfexplorer@latest
```

or download the latest release binary (Linux amd64/arm64):

```sh
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL -o ebpfexplorer "https://github.com/noboruma/ebpfexplorer/releases/latest/download/ebpfexplorer-linux-${arch}"
chmod +x ebpfexplorer
sudo ./ebpfexplorer
```

or download the binaries in the release section.

Same keys on every screen: `[↑/↓]` move, `[←/→]` scroll sideways to read anything cut off with `…`
(columns and header lines; `←` at the left edge goes back), `[enter]` open, `[esc]` back.

## Programs Explorer (Root View)

Shows every loaded BPF program and where it is attached. `[x]` toggles XDP only, `[/]` filters on name.

```
 eBPF explorer  programs
 ID      Name                 Type           Maps  Tag               Attached
─────────────────────────────────────────────────────────────────────────────────────────────────
 41      xdp_proxy_filter     XDP            2     a1b2c3d4e5f60718  xdp@eth0 (native)
 42      tc_bandwidth         SchedCLS       1     0f1e2d3c4b5a6978  tcx@eth0
 57      trace_connect        Kprobe         1     9988776655443322
 10122   sd_devices           CGroupDevice   0     ee0e253c78993a24  cgroup/device@systemd-udev…
4 programs
[↑/↓] move  [←/→] scroll  [enter] open  [x] XDP only  [/] filter  [r] refresh programs  [q] quit
```

## Maps Explorer

After selecting a program, `ebpfexplorer` shows the maps a program uses, with their entry count (counted in the background) and whether a format is defined.
The header shows where the program is attached and which processes hold it open.

```
 eBPF explorer  programs › prog 41 xdp_proxy_filter
attached: xdp@eth0 (native)  •  processes: proxy-agent (pid 2211)
 ID      Name                Type            Key   Value  MaxEntries  Entries     Flags  Format
─────────────────────────────────────────────────────────────────────────────────────────────────
 12      flows               PerCPUHash      12    16     10000000    counting…   0x0    key+val
 13      blocklist           LPMTrie         8     4      65536       1532        0x0
[↑/↓] move  [←/→] scroll  [enter] open  [e] edit format  [esc] back  [r] refresh maps  [q] quit
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
[↑/↓ pgup/pgdn g/G] move  [←/→] scroll  [enter] open  [/] search  [e] edit format  [esc] back  [r] refresh map  [q] quit
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
[↑/↓] move  [←/→] scroll  [e] edit format  [esc] back  [r] refresh entry  [q] quit
```

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
[tab] switch key/value  [enter] save  [esc] cancel
```

Note that IPs are correctly formatted as human readable: `1.2.3.4`

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
      "value": "struct { __u64 packets; __u64 bytes; }"
    }
  }
}
```

### Formats bundled in the binary

A formats file can also be appended to the binary, so a single file carries them. Bundled formats are
read-only defaults: a format saved with `[e]` takes precedence (and is saved to the file above, never to
the binary), and clearing it falls back to the bundled one.

With the Makefile:

```sh
make bundle                  # build ./ebpfexplorer if missing, bundle formats.json (replaces any bundled formats)
make bundle BIN=dist/ebpfexplorer-linux-arm64 CFG=team.json
make show                    # print the bundled formats
make unbundle                # remove them
```

or by hand:

```sh
# bundle formats.json into ebpfexplorer, replacing any formats already bundled
# layout: <binary><formats JSON><JSON length, 16 digits>EBPFXCFG
bin=ebpfexplorer cfg=formats.json
rm -f "$bin.tmp"
if [ "$(tail -c 8 "$bin" | tr -d '\0')" = EBPFXCFG ]; then
  n=$(tail -c 24 "$bin" | head -c 16); head -c -$((10#$n + 24)) "$bin" > "$bin.tmp"
else
  cp "$bin" "$bin.tmp"
fi
{ cat "$cfg"; printf '%016d%s' "$(stat -c %s "$cfg")" EBPFXCFG; } >> "$bin.tmp"
chmod +x "$bin.tmp" && mv "$bin.tmp" "$bin"

# inspect what is bundled
n=$(tail -c 24 ebpfexplorer-bundled | head -c 16); tail -c $((10#$n + 24)) ebpfexplorer-bundled | head -c $((10#$n))

# remove the bundled formats
n=$(tail -c 24 ebpfexplorer-bundled | head -c 16); head -c -$((10#$n + 24)) ebpfexplorer-bundled > ebpfexplorer
```

Tools that rewrite
the ELF, such as `strip` or `upx`, drop the bundled formats.

## Keybind: Refresh

`[r]` refreshes only what you are looking at: the program list, the program's maps, the whole map, or a single entry.
