package main

// One list/scroll model shared by every screen, so navigation is the same
// everywhere: ↑/↓ pgup/pgdn g/G move, ←/→ scroll horizontally through text
// cut off with "…" (header lines included), enter opens, esc goes back.

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-runewidth"
)

const hStep = 8

type column struct {
	title string
	width int
}

// pane is the cursor and scroll state of one screen.
type pane struct {
	cur  int // selected row (lists only)
	off  int // first row on screen
	hOff int // horizontal scroll, in cells
}

// move handles a vertical navigation key for a list of n rows, rows of
// which fit on screen. It reports whether key was a navigation key.
func (p *pane) move(key string, n, rows int) bool {
	switch key {
	case "up", "k":
		p.cur--
	case "down", "j":
		p.cur++
	case "pgup", "ctrl+u":
		p.cur -= rows
	case "pgdown", "ctrl+d", " ":
		p.cur += rows
	case "home", "g":
		p.cur = 0
	case "end", "G":
		p.cur = n - 1
	default:
		return false
	}
	p.clamp(n, rows)
	return true
}

// clamp keeps the cursor in range and on screen.
func (p *pane) clamp(n, rows int) {
	p.cur = max(0, min(p.cur, n-1))
	if p.cur < p.off {
		p.off = p.cur
	}
	if p.cur >= p.off+rows {
		p.off = p.cur - rows + 1
	}
	p.off = max(0, p.off)
}

// scrollText handles a vertical key for a cursor-less text of n lines: the
// cursor is the top line.
func (p *pane) scrollText(key string, n, rows int) bool {
	last := max(0, n-rows)
	switch key {
	case "up", "k":
		p.off--
	case "down", "j":
		p.off++
	case "pgup", "ctrl+u":
		p.off -= rows
	case "pgdown", "ctrl+d", " ":
		p.off += rows
	case "home", "g":
		p.off = 0
	case "end", "G":
		p.off = last
	default:
		return false
	}
	p.off = max(0, min(p.off, last))
	return true
}

// tableSpec describes a list: its columns and the full, untruncated cells of
// row i. Column 0 (IDs, row numbers) never scrolls horizontally.
type tableSpec struct {
	cols  []column
	n     int
	row   func(i int) []string
	empty string // shown when n == 0
}

// render draws the header and the rows on screen only, so it costs the same
// for 10 rows as for 10 million.
func (t tableSpec) render(p pane, rows int) string {
	var b strings.Builder
	head := make([]string, len(t.cols))
	for i, c := range t.cols {
		head[i] = cell(c.title, c.width)
	}
	b.WriteString(headerStyle.Render(strings.Join(head, "")) + "\n")
	if t.n == 0 && t.empty != "" {
		b.WriteString("  " + t.empty + "\n")
	}
	for r := p.off; r < min(t.n, p.off+rows); r++ {
		var line strings.Builder
		for c, f := range t.row(r) {
			if c > 0 {
				f = scrollLeft(f, p.hOff, t.cols[c].width)
			}
			line.WriteString(cell(f, t.cols[c].width))
		}
		if r == p.cur {
			b.WriteString(selectedStyle.Render(line.String()))
		} else {
			b.WriteString(line.String())
		}
		b.WriteString("\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// overflow is how far the rows on screen can scroll: the largest amount by
// which a cell is wider than its column.
func (t tableSpec) overflow(p pane, rows int) int {
	over := 0
	for r := p.off; r < min(t.n, p.off+rows); r++ {
		for c, f := range t.row(r) {
			if c > 0 {
				over = max(over, lineOverflow(f, t.cols[c].width))
			}
		}
	}
	return over
}

// scrollLine shifts a full-width line (header line, detail text) by off
// cells and cuts it to width, marking hidden text on either side with "…".
func scrollLine(s string, off, width int) string {
	return ansi.Truncate(scrollLeft(s, off, width), max(1, width), "…")
}

// lineOverflow is how far text needs to scroll to show its end in width.
func lineOverflow(s string, width int) int {
	return max(0, ansi.StringWidth(s)-width)
}

// scrollLeft hides the first cells of s so that it scrolls by off, but never
// further than needed to show its end in width: text that fits doesn't move,
// and each piece of text stops at its own end. The cut is marked with "…".
func scrollLeft(s string, off, width int) string {
	off = min(off, lineOverflow(s, width))
	if off <= 0 {
		return s
	}
	return ansi.TruncateLeft(s, off+1, "…")
}

// cell renders s left-aligned in a column of width w plus 1 space each side.
func cell(s string, w int) string {
	return " " + runewidth.FillRight(runewidth.Truncate(s, w, "…"), w) + " "
}

type colSpec struct {
	title  string
	min    int
	weight int // share of leftover width
}

func fitColumns(width int, specs []colSpec) []column {
	used, weights := 0, 0
	for _, s := range specs {
		used += s.min + 2 // cell padding
		weights += s.weight
	}
	extra := max(0, width-used)
	cols := make([]column, len(specs))
	for i, s := range specs {
		w := s.min
		if weights > 0 {
			w += extra * s.weight / weights
		}
		cols[i] = column{title: s.title, width: w}
	}
	return cols
}
