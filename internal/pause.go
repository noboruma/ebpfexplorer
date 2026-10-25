package internal

// Pausing programs ([D]). The kernel can't pause a program, but a bpf_link
// can be pointed at another one: pausing swaps a "do nothing" program of the
// same type into each of the program's XDP, tcx, netkit and cgroup links
// (BPF_LINK_UPDATE), resuming swaps the original back. The link and the
// process owning it stay the same.
//
// While paused, the link no longer holds the original program, so the
// explorer keeps it open until it is resumed; quitting resumes everything.
// Other attachments (tracing links, legacy cgroup and XDP, perf events)
// can't be swapped this way and are left alone.

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

const (
	// bpfFReplace (BPF_F_REPLACE) only updates a link still running the
	// given old program, so a link its owner changed meanwhile is left as is.
	bpfFReplace = 1 << 2
	// bpfFXDPHasFrags (BPF_F_XDP_HAS_FRAGS) loads an XDP program that
	// handles multi-buffer packets.
	bpfFXDPHasFrags = 1 << 5

	noopName = "ebpfx_paused"
)

// pausedLink is a link running the no-op in place of its program.
type pausedLink struct {
	id     link.ID
	label  string        // where it is attached, e.g. "xdp@eth0"
	orig   *ebpf.Program // held open: the link no longer keeps it alive
	origID ebpf.ProgramID
	noop   ebpf.ProgramID
}

// pauseSet holds the paused links; it is shared by every copy of the model.
type pauseSet struct {
	links map[link.ID]*pausedLink
}

func newPauseSet() *pauseSet { return &pauseSet{links: map[link.ID]*pausedLink{}} }

type linkUpdater interface {
	UpdateArgs(link.RawLinkUpdateOptions) error
}

func pausable(a attachment) bool {
	if a.linkID == 0 {
		return false
	}
	switch a.linkType {
	case link.XDPType, link.TCXType, link.NetkitType, link.CgroupType:
		return true
	}
	return false
}

// pausableLinks lists the attachments of p that pausing swaps.
func pausableLinks(p progRow) []attachment {
	var out []attachment
	for _, a := range p.Attachments {
		if pausable(a) {
			out = append(out, a)
		}
	}
	return out
}

// pausedOf lists the paused links of program id, seen from the original
// program or from the no-op standing in for it.
func (s *pauseSet) pausedOf(id ebpf.ProgramID) []*pausedLink {
	var out []*pausedLink
	for _, p := range s.links {
		if p.origID == id || p.noop == id {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *pausedLink) int { return cmp.Compare(a.id, b.id) })
	return out
}

func pausedLabels(ps []*pausedLink) string {
	labels := make([]string, len(ps))
	for i, p := range ps {
		labels[i] = p.label
	}
	return strings.Join(labels, ", ")
}

// pause swaps the no-op into each of prog's links in as. It stops at the
// first error; the links already swapped stay paused.
func (s *pauseSet) pause(prog ebpf.ProgramID, as []attachment) (int, error) {
	n := 0
	for _, a := range as {
		if _, ok := s.links[a.linkID]; ok {
			continue
		}
		p, err := pauseLink(prog, a)
		if err != nil {
			return n, fmt.Errorf("%s: %w", a.label, err)
		}
		s.links[a.linkID] = p
		n++
	}
	return n, nil
}

func pauseLink(progID ebpf.ProgramID, a attachment) (*pausedLink, error) {
	l, err := link.NewFromID(a.linkID)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return nil, err
	}
	if info.Program != progID {
		return nil, fmt.Errorf("link %d now runs program %d", a.linkID, info.Program)
	}
	upd, ok := l.(linkUpdater)
	if !ok {
		return nil, errors.New("link can't be updated")
	}
	orig, err := ebpf.NewProgramFromID(progID)
	if err != nil {
		return nil, err
	}
	spec, err := noopSpec(info.Type, linkAttachType(info), orig.Type())
	if err != nil {
		orig.Close()
		return nil, err
	}
	noop, err := swapIn(upd, spec, orig)
	if err != nil && spec.Type == ebpf.XDP {
		// An XDP program handling multi-buffer packets (xdp.frags) can only
		// be replaced by another one that does.
		spec.Flags |= bpfFXDPHasFrags
		if id, err2 := swapIn(upd, spec, orig); err2 == nil {
			noop, err = id, nil
		}
	}
	if err != nil {
		orig.Close()
		return nil, err
	}
	return &pausedLink{id: a.linkID, label: a.label, orig: orig, origID: progID, noop: noop}, nil
}

// swapIn loads the no-op and swaps it in place of orig.
func swapIn(upd linkUpdater, spec *ebpf.ProgramSpec, orig *ebpf.Program) (ebpf.ProgramID, error) {
	noop, err := ebpf.NewProgram(spec)
	if err != nil {
		return 0, fmt.Errorf("loading the no-op: %w", err)
	}
	defer noop.Close() // the link holds it once swapped in
	if err := upd.UpdateArgs(link.RawLinkUpdateOptions{New: noop, Old: orig, Flags: bpfFReplace}); err != nil {
		return 0, err
	}
	info, err := noop.Info()
	if err != nil {
		return 0, err
	}
	id, _ := info.ID()
	return id, nil
}

func linkAttachType(info *link.Info) ebpf.AttachType {
	switch {
	case info.TCX() != nil:
		return ebpf.AttachType(info.TCX().AttachType)
	case info.Netkit() != nil:
		return ebpf.AttachType(info.Netkit().AttachType)
	case info.Cgroup() != nil:
		return ebpf.AttachType(info.Cgroup().AttachType)
	}
	return ebpf.AttachNone
}

// noopSpec is the program standing in for a paused one of type t: it lets
// everything through, as if nothing were attached.
func noopSpec(lt link.Type, at ebpf.AttachType, t ebpf.ProgramType) (*ebpf.ProgramSpec, error) {
	var ret int32
	switch {
	case lt == link.XDPType && t == ebpf.XDP:
		ret = 2 // XDP_PASS
	case lt == link.TCXType, lt == link.NetkitType:
		ret = -1 // TCX_NEXT, NETKIT_NEXT: on to the next program, or the stack
	case lt == link.CgroupType && cgroupHooks[t] != nil:
		ret = 1 // allow
	default:
		return nil, fmt.Errorf("%s programs on %s links can't be paused", t, linkTypeName(lt))
	}
	return &ebpf.ProgramSpec{
		Name:         noopName,
		Type:         t,
		AttachType:   at,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, ret), asm.Return()},
		License:      "GPL",
	}, nil
}

// resume swaps the original programs back into ps and forgets them, even
// when that fails: a link that is gone or changed by its owner can't be
// resumed anymore.
func (s *pauseSet) resume(ps []*pausedLink) error {
	var errs []error
	for _, p := range ps {
		if err := resumeLink(p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.label, err))
		}
		s.forget(p)
	}
	return errors.Join(errs...)
}

func (s *pauseSet) resumeAll() error {
	ps := make([]*pausedLink, 0, len(s.links))
	for _, p := range s.links {
		ps = append(ps, p)
	}
	return s.resume(ps)
}

func (s *pauseSet) forget(p *pausedLink) {
	if p.orig != nil {
		p.orig.Close()
	}
	delete(s.links, p.id)
}

func resumeLink(p *pausedLink) error {
	l, err := link.NewFromID(p.id)
	if err != nil {
		return fmt.Errorf("link is gone: %w", err)
	}
	defer l.Close()
	upd, ok := l.(linkUpdater)
	if !ok {
		return errors.New("link can't be updated")
	}
	noop, err := ebpf.NewProgramFromID(p.noop)
	if err != nil {
		return fmt.Errorf("link no longer runs the no-op: %w", err)
	}
	defer noop.Close()
	return upd.UpdateArgs(link.RawLinkUpdateOptions{New: p.orig, Old: noop, Flags: bpfFReplace})
}

// apply brings a fresh program list in line with the pauses: links that are
// gone are forgotten (only from a complete list), and each paused link is
// listed on its original program as "xdp@eth0 (paused)".
func (s *pauseSet) apply(rows []progRow, complete bool) {
	if complete {
		seen := map[link.ID]bool{}
		for _, r := range rows {
			for _, a := range r.Attachments {
				seen[a.linkID] = true
			}
		}
		for id, p := range s.links {
			if !seen[id] {
				s.forget(p)
			}
		}
	}
	for i, r := range rows {
		changed := false
		for _, p := range s.pausedOf(r.ID) {
			if p.origID == r.ID {
				rows[i].Attachments = append(rows[i].Attachments, attachment{label: p.label + " (paused)"})
				changed = true
			}
		}
		if changed {
			rows[i].Attached = attachmentLabels(rows[i].Attachments)
		}
	}
}
