// Package tui is a terminal ops dashboard for a running openconnectd. It is a
// thin pkg/api client: it polls instances and live sessions, and offers a few
// safe actions (kick a session, toggle an instance). Works against a local or
// remote daemon.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/reloadlife/openconnectd/pkg/api"
)

const pollEvery = 3 * time.Second

// Run starts the dashboard against the daemon at baseURL.
func Run(baseURL, token string) error {
	c, err := api.NewClient(baseURL, api.WithToken(token))
	if err != nil {
		return err
	}
	m := model{client: c, base: baseURL, focus: paneInstances}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

type pane int

const (
	paneInstances pane = iota
	paneSessions
)

type model struct {
	client    *api.Client
	base      string
	instances []api.Instance
	sessions  []api.Session
	focus     pane
	cursor    int
	status    string
	err       error
	w, h      int
}

type dataMsg struct {
	instances []api.Instance
	sessions  []api.Session
	err       error
}
type tickMsg time.Time
type actionMsg struct{ status string }

func (m model) Init() tea.Cmd { return tea.Batch(m.fetch(), tick()) }

func tick() tea.Cmd {
	return tea.Tick(pollEvery, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) fetch() tea.Cmd {
	c := m.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ins, err := c.ListInstances(ctx)
		if err != nil {
			return dataMsg{err: err}
		}
		sess, err := c.Sessions(ctx, "")
		if err != nil {
			return dataMsg{err: err}
		}
		sort.Slice(ins, func(i, j int) bool { return ins[i].Name < ins[j].Name })
		sort.Slice(sess, func(i, j int) bool { return sess[i].CommonName < sess[j].CommonName })
		return dataMsg{instances: ins, sessions: sess}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		return m, tea.Batch(m.fetch(), tick())
	case dataMsg:
		if msg.err != nil {
			m.err = msg.err
		} else {
			m.err = nil
			m.instances, m.sessions = msg.instances, msg.sessions
			m.clampCursor()
		}
	case actionMsg:
		m.status = msg.status
		return m, m.fetch()
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m model) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.focus = 1 - m.focus
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < m.rows()-1 {
			m.cursor++
		}
	case "r":
		return m, m.fetch()
	case "x":
		return m, m.kick()
	case "e":
		return m, m.toggle()
	}
	return m, nil
}

func (m model) rows() int {
	if m.focus == paneInstances {
		return len(m.instances)
	}
	return len(m.sessions)
}

func (m *model) clampCursor() {
	if m.cursor >= m.rows() {
		m.cursor = m.rows() - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// kick disconnects the selected live session.
func (m model) kick() tea.Cmd {
	if m.focus != paneSessions || m.cursor >= len(m.sessions) {
		return nil
	}
	s := m.sessions[m.cursor]
	c := m.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Disconnect(ctx, s.InstanceName, s.CommonName); err != nil {
			return actionMsg{status: "kick failed: " + err.Error()}
		}
		return actionMsg{status: fmt.Sprintf("disconnected %s@%s", s.CommonName, s.InstanceName)}
	}
}

// toggle enables/disables the selected instance.
func (m model) toggle() tea.Cmd {
	if m.focus != paneInstances || m.cursor >= len(m.instances) {
		return nil
	}
	in := m.instances[m.cursor]
	c := m.client
	want := !in.Enabled
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := c.PatchInstance(ctx, in.Name, map[string]any{"enabled": want}); err != nil {
			return actionMsg{status: "toggle failed: " + err.Error()}
		}
		state := "disabled"
		if want {
			state = "enabled"
		}
		return actionMsg{status: fmt.Sprintf("%s %s", state, in.Name)}
	}
}

// --- view ---

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	headStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	selStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("42"))
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	activeTab   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	inactiveTab = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

func (m model) View() string {
	var b strings.Builder
	fmt.Fprintln(&b, titleStyle.Render("openconnectd")+dimStyle.Render("  "+m.base))
	fmt.Fprintln(&b, m.tabs())
	fmt.Fprintln(&b)

	if m.focus == paneInstances {
		b.WriteString(m.instanceTable())
	} else {
		b.WriteString(m.sessionTable())
	}

	fmt.Fprintln(&b)
	if m.err != nil {
		fmt.Fprintln(&b, errStyle.Render("error: "+m.err.Error()))
	} else if m.status != "" {
		fmt.Fprintln(&b, dimStyle.Render(m.status))
	}
	fmt.Fprintln(&b, dimStyle.Render("tab switch · ↑↓ move · e toggle instance · x kick session · r refresh · q quit"))
	return b.String()
}

func (m model) tabs() string {
	ins := fmt.Sprintf("Instances (%d)", len(m.instances))
	ses := fmt.Sprintf("Sessions (%d)", len(m.sessions))
	if m.focus == paneInstances {
		return activeTab.Render(ins) + "   " + inactiveTab.Render(ses)
	}
	return inactiveTab.Render(ins) + "   " + activeTab.Render(ses)
}

func (m model) instanceTable() string {
	var b strings.Builder
	fmt.Fprintln(&b, headStyle.Render(fmt.Sprintf("%-16s %-6s %-8s %-22s %-8s %s",
		"NAME", "UP", "CAMOUFL", "ENDPOINT", "CLIENTS", "AUTH")))
	if len(m.instances) == 0 {
		fmt.Fprintln(&b, dimStyle.Render("  no instances"))
	}
	for i, in := range m.instances {
		row := fmt.Sprintf("%-16s %-6s %-8s %-22s %-8d %s",
			trunc(in.Name, 16), yesno(in.Up), yesno(in.Camouflage.Enabled),
			trunc(in.PublicEndpoint, 22), in.ClientCount, in.AuthMode)
		b.WriteString(m.line(i, row))
	}
	return b.String()
}

func (m model) sessionTable() string {
	var b strings.Builder
	fmt.Fprintln(&b, headStyle.Render(fmt.Sprintf("%-16s %-14s %-16s %-16s %-10s %-6s %s",
		"USER", "INSTANCE", "VPN IP", "REMOTE IP", "RX/TX", "DTLS", "UPTIME")))
	if len(m.sessions) == 0 {
		fmt.Fprintln(&b, dimStyle.Render("  no live sessions"))
	}
	for i, s := range m.sessions {
		row := fmt.Sprintf("%-16s %-14s %-16s %-16s %-10s %-6s %s",
			trunc(s.CommonName, 16), trunc(s.InstanceName, 14), s.VPNAddress, s.RemoteIP,
			bytesShort(s.RxBytes)+"/"+bytesShort(s.TxBytes), yesno(s.DTLS), uptime(s.ConnectedAt))
		b.WriteString(m.line(i, row))
	}
	return b.String()
}

// line renders one row, highlighted when it is under the cursor.
func (m model) line(i int, row string) string {
	if i == m.cursor {
		return selStyle.Render(row) + "\n"
	}
	return row + "\n"
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func bytesShort(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func uptime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}
