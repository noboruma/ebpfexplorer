package internal

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// programHolders lists the processes holding the program open. A "prog_id:"
// line appears both in program fds and in the fds of links attaching that
// program, so loaders that keep only the link are found too.
func programHolders(id ebpf.ProgramID) []string { return fdHolders("prog_id", uint32(id)) }

// mapHolders lists the processes holding the map open.
func mapHolders(id ebpf.MapID) []string { return fdHolders("map_id", uint32(id)) }

// fdHolders scans /proc/<pid>/fdinfo for fds whose "<field>:" line is id.
func fdHolders(field string, id uint32) []string {
	want := fmt.Sprintf("%s:\t%d", field, id)
	self := strconv.Itoa(os.Getpid())
	var out []string
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid := p.Name()
		if pid == self || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		fds, err := os.ReadDir("/proc/" + pid + "/fdinfo")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			data, err := os.ReadFile("/proc/" + pid + "/fdinfo/" + fd.Name())
			if err != nil || !containsLine(string(data), want) {
				continue
			}
			comm, _ := os.ReadFile("/proc/" + pid + "/comm")
			out = append(out, fmt.Sprintf("%s (pid %s)", strings.TrimSpace(string(comm)), pid))
			break // one entry per process
		}
	}
	return out
}

func containsLine(s, line string) bool {
	for l := range strings.Lines(s) {
		if strings.TrimRight(l, "\n") == line {
			return true
		}
	}
	return false
}
