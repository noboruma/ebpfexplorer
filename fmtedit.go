package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	labelStyle = lipgloss.NewStyle().Bold(true)
	panelStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1)
)

// fmtEditor edits the key and value C definitions of one map.
type fmtEditor struct {
	target  mapRow
	inputs  [2]textinput.Model // 0 = key, 1 = value
	focus   int
	parsed  [2]*ctype
	errs    [2]string
	saveErr string
	path    string // where the format is saved, shown to the user
}

func newFmtEditor(mp mapRow, d formatDef) *fmtEditor {
	e := &fmtEditor{target: mp}
	for i, v := range []string{d.Key, d.Value} {
		in := textinput.New()
		in.Prompt = ""
		in.CharLimit = 4096
		in.Placeholder = "empty = show as hex, e.g. struct { __u32 ip; __u16 port; }"
		in.SetValue(v)
		e.inputs[i] = in
	}
	e.inputs[0].Focus()
	e.validate()
	return e
}

func (e *fmtEditor) sizes() [2]int {
	return [2]int{int(e.target.KeySize), int(e.target.ValueSize)}
}

// validate parses both inputs and checks them against the map's sizes.
func (e *fmtEditor) validate() {
	for i := range e.inputs {
		e.parsed[i], e.errs[i] = nil, ""
		t, err := parseOptional(e.inputs[i].Value())
		switch {
		case err != nil:
			e.errs[i] = err.Error()
		case t != nil && t.size != e.sizes()[i]:
			e.errs[i] = fmt.Sprintf("definition is %d bytes but the map's %s is %d bytes",
				t.size, []string{"key", "value"}[i], e.sizes()[i])
		default:
			e.parsed[i] = t
		}
	}
}

func (e *fmtEditor) valid() bool { return e.errs[0] == "" && e.errs[1] == "" }

func (m model) updateFmtEditor(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	e := m.fmtEdit
	switch msg.String() {
	case "esc":
		m.fmtEdit = nil
		return m, nil
	case "tab", "shift+tab", "up", "down":
		e.inputs[e.focus].Blur()
		e.focus = 1 - e.focus
		e.inputs[e.focus].Focus()
		return m, textinput.Blink
	case "enter":
		if !e.valid() {
			return m, nil
		}
		def := formatDef{
			Key:   strings.TrimSpace(e.inputs[0].Value()),
			Value: strings.TrimSpace(e.inputs[1].Value()),
		}
		if err := m.formats.set(e.target, def, compiledFormat{key: e.parsed[0], value: e.parsed[1]}); err != nil {
			e.saveErr = err.Error()
			return m, nil
		}
		m.fmtEdit = nil
		return m, m.formatsChanged()
	}
	var cmd tea.Cmd
	e.inputs[e.focus], cmd = e.inputs[e.focus].Update(msg)
	e.validate()
	e.saveErr = ""
	return m, cmd
}

func (e *fmtEditor) view(width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s map %d %q (key %dB, value %dB)\n",
		labelStyle.Render("Format for"), e.target.ID, e.target.Name, e.target.KeySize, e.target.ValueSize)
	where := "saved by map name, so it applies again after the program is reloaded"
	if e.path != "" {
		where = "saved by map name in " + e.path
	}
	b.WriteString(crumbStyle.Render(where) + "\n\n")

	inner := max(20, width-6)
	for i, label := range []string{"Key", "Value"} {
		e.inputs[i].Width = inner - 2
		marker := "  "
		if i == e.focus {
			marker = "▸ "
		}
		b.WriteString(marker + labelStyle.Render(label) + "\n  " + e.inputs[i].View() + "\n  ")
		switch {
		case e.errs[i] != "":
			b.WriteString(errStyle.Render("✗ " + e.errs[i]))
		case e.parsed[i] != nil:
			b.WriteString(okStyle.Render(fmt.Sprintf("✓ %d bytes", e.parsed[i].size)))
		default:
			b.WriteString(crumbStyle.Render("shown as hex"))
		}
		b.WriteString("\n\n")
	}
	if e.saveErr != "" {
		b.WriteString(errStyle.Render("save failed: "+e.saveErr) + "\n\n")
	}
	b.WriteString(crumbStyle.Render(
		"types:  char short int long unsigned…  __u8…__u64 __s8…__s64 uint8_t…  __be16/32/64  bool float double\n" +
			"extras: ipv4 ipv6 mac, x8…x64 (hex); arrays a[N], nested struct/union, pointers\n" +
			"attrs:  __attribute__((packed)), __attribute__((aligned(N)))"))
	return panelStyle.Width(inner + 2).Render(b.String())
}
