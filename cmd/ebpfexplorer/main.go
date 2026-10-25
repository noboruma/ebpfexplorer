// Command ebpfexplorer is a terminal UI to explore the BPF programs, maps and
// map entries loaded on the machine. Needs CAP_SYS_ADMIN / CAP_BPF (run with
// sudo).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/noboruma/ebpfexplorer/internal"
)

func main() {
	var opts internal.Options
	flag.BoolVar(&opts.AllMaps, "maps", false, "start on the list of all maps instead of the programs")
	flag.BoolVar(&opts.AllowWrite, "allow-write", false, "allow writing map entries ([w] on an entry) and pausing programs ([D]); read-only otherwise")
	flag.BoolVar(&opts.AllowWrite, "w", false, "shorthand for --allow-write")
	flag.BoolVar(&opts.GlobalConfig, "global-config", false,
		"load/store formats in $XDG_CONFIG_HOME/ebpfexplorer/formats.json instead of "+internal.LocalFormatsFile+" next to the binary")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "warning: not running as root; listing BPF objects usually needs CAP_SYS_ADMIN/CAP_BPF")
	}
	if err := internal.Run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
