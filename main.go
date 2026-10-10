// Command goportforwarding is a small desktop GUI for a single SSH local
// port-forwarding tunnel (the equivalent of `ssh -N -L ...`).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/ssh"

	"goportforwarding/profile"
	"goportforwarding/tunnel"
)

type state int

const (
	stateIdle state = iota
	stateConnecting
	stateConnected
)

const maxLogLines = 200

// Authentication choices, in display order, keyed by profile.Auth* value.
var (
	authModes  = []string{profile.AuthKey, profile.AuthAgent, profile.AuthPassword}
	authLabels = map[string]string{
		profile.AuthKey:      "Private key",
		profile.AuthAgent:    "ssh-agent",
		profile.AuthPassword: "Password",
	}
)

type ui struct {
	win fyne.Window

	sshHost, sshPort, user, keyPath *widget.Entry
	password                        *widget.Entry
	localPort, destHost, destPort   *widget.Entry
	authMode                        *widget.RadioGroup
	form                            *widget.Form
	credItem                        *widget.FormItem
	keyRow, agentInfo               fyne.CanvasObject
	profileSel                      *widget.Select
	saveBtn, deleteBtn              *widget.Button
	browse, startBtn, stopBtn       *widget.Button
	status, localAddr               *widget.Label
	logText                         *widget.Label
	logScroll                       *container.Scroll
	logLines                        []string

	// Owned by the main (UI) goroutine.
	state  state
	cancel context.CancelFunc
	tun    *tunnel.Tunnel

	// store is nil if the profiles file could not be read, so that it is
	// never overwritten.
	store       *profile.Store
	profilePath string
}

func main() {
	a := app.NewWithID("io.github.tthogho1.goportforwarding")
	w := a.NewWindow("SSH Port Forwarding")
	u := &ui{win: w}
	w.SetContent(u.build())
	w.Resize(fyne.NewSize(560, 560))
	w.SetOnClosed(u.shutdown)
	u.setState(stateIdle, "Not connected", "")
	u.loadProfiles()
	w.ShowAndRun()
}

func (u *ui) build() fyne.CanvasObject {
	u.sshHost = entry("bastion.example.com", "")
	u.sshPort = entry("22", "22")
	u.user = entry("alice", "")
	u.keyPath = entry("path to private key (e.g. id_ed25519)", defaultKeyPath())
	u.localPort = entry("15432", "")
	u.destHost = entry("db.internal.example (or localhost)", "")
	u.destPort = entry("5432", "")

	u.password = widget.NewPasswordEntry()
	u.password.SetPlaceHolder("SSH password (not saved)")
	u.password.OnSubmitted = func(string) { u.start() }

	u.browse = widget.NewButton("Browse…", u.pickKey)
	u.keyRow = container.NewBorder(nil, nil, nil, u.browse, u.keyPath)

	agentText := "Uses the keys loaded in your ssh-agent (add one with ssh-add)."
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		agentText = "No ssh-agent found: SSH_AUTH_SOCK is not set for this app."
	}
	info := widget.NewLabel(agentText)
	info.Wrapping = fyne.TextWrapWord
	u.agentInfo = info

	u.credItem = widget.NewFormItem("Private key file", u.keyRow)
	var labels []string
	for _, m := range authModes {
		labels = append(labels, authLabels[m])
	}
	u.authMode = widget.NewRadioGroup(labels, u.setAuthMode)
	u.authMode.Horizontal = true
	u.authMode.Required = true

	u.profileSel = widget.NewSelect(nil, u.selectProfile)
	u.profileSel.PlaceHolder = "(unsaved)"
	u.saveBtn = widget.NewButton("Save…", u.saveProfile)
	u.deleteBtn = widget.NewButton("Delete", u.deleteProfile)
	profileRow := container.NewBorder(nil, nil, widget.NewLabel("Profile"),
		container.NewHBox(u.saveBtn, u.deleteBtn), u.profileSel)

	u.form = widget.NewForm(
		widget.NewFormItem("SSH server host", u.sshHost),
		widget.NewFormItem("SSH server port", u.sshPort),
		widget.NewFormItem("SSH username", u.user),
		widget.NewFormItem("Authentication", u.authMode),
		u.credItem,
		widget.NewFormItem("Local port", u.localPort),
		widget.NewFormItem("Destination host", u.destHost),
		widget.NewFormItem("Destination port", u.destPort),
	)
	u.authMode.SetSelected(authLabels[profile.AuthKey])
	hint := widget.NewLabel("The destination is reached from the SSH server's network. " +
		"Your app connects to 127.0.0.1:<local port>.")
	hint.Wrapping = fyne.TextWrapWord
	hint.Importance = widget.LowImportance

	u.startBtn = widget.NewButton("Start Forwarding", u.start)
	u.startBtn.Importance = widget.HighImportance
	u.stopBtn = widget.NewButton("Stop Forwarding", u.stop)

	u.status = widget.NewLabel("")
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.status.Wrapping = fyne.TextWrapWord
	u.localAddr = widget.NewLabel("")
	u.localAddr.TextStyle = fyne.TextStyle{Monospace: true}

	u.logText = widget.NewLabel("")
	u.logText.Wrapping = fyne.TextWrapWord
	u.logText.TextStyle = fyne.TextStyle{Monospace: true}
	u.logScroll = container.NewVScroll(u.logText)
	u.logScroll.SetMinSize(fyne.NewSize(0, 120))

	top := container.NewVBox(
		profileRow,
		widget.NewSeparator(),
		u.form,
		hint,
		container.NewGridWithColumns(2, u.startBtn, u.stopBtn),
		widget.NewSeparator(),
		u.status,
		u.localAddr,
		widget.NewLabel("Log"),
	)
	return container.NewBorder(top, nil, nil, nil, u.logScroll)
}

// auth returns the selected authentication method as a profile.Auth* value.
func (u *ui) auth() string {
	for _, m := range authModes {
		if authLabels[m] == u.authMode.Selected {
			return m
		}
	}
	return profile.AuthKey
}

// setAuthMode swaps the credential row to match the selected method.
func (u *ui) setAuthMode(string) {
	if u.form == nil {
		return
	}
	switch u.auth() {
	case profile.AuthPassword:
		u.credItem.Text, u.credItem.Widget = "Password", u.password
	case profile.AuthAgent:
		u.credItem.Text, u.credItem.Widget = "Keys", u.agentInfo
	default:
		u.credItem.Text, u.credItem.Widget = "Private key file", u.keyRow
	}
	if u.auth() != profile.AuthPassword {
		u.password.SetText("")
	}
	u.form.Refresh()
}

// loadProfiles reads the profiles file and selects the last-used profile.
func (u *ui) loadProfiles() {
	path, err := profile.DefaultPath()
	if err == nil {
		u.profilePath = path
		u.store, err = profile.Load(path)
	}
	if err != nil {
		u.logf("profiles unavailable: %v", err)
		u.refreshProfileButtons()
		return
	}
	u.profileSel.SetOptions(u.store.Names())
	if _, ok := u.store.Get(u.store.Last); ok {
		u.profileSel.SetSelected(u.store.Last)
	}
	u.refreshProfileButtons()
}

func (u *ui) refreshProfileButtons() {
	idle := u.state == stateIdle
	setEnabled(u.profileSel, idle && u.store != nil)
	setEnabled(u.saveBtn, idle && u.store != nil)
	setEnabled(u.deleteBtn, idle && u.store != nil && u.profileSel.Selected != "")
}

func setEnabled(w fyne.Disableable, on bool) {
	if on {
		w.Enable()
	} else {
		w.Disable()
	}
}

// selectProfile fills the form from the chosen profile.
func (u *ui) selectProfile(name string) {
	p, ok := u.store.Get(name)
	if !ok {
		return
	}
	portText := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	u.sshHost.SetText(p.SSHHost)
	u.sshPort.SetText(portText(p.SSHPort))
	u.user.SetText(p.User)
	if label, ok := authLabels[p.Auth]; ok {
		u.authMode.SetSelected(label)
	}
	u.keyPath.SetText(p.KeyPath)
	u.localPort.SetText(portText(p.LocalPort))
	u.destHost.SetText(p.DestHost)
	u.destPort.SetText(portText(p.DestPort))
	u.password.SetText("") // a password typed for another server must not carry over

	if u.store.Last != name {
		u.store.Last = name
		u.writeProfiles()
	}
	u.refreshProfileButtons()
}

// formProfile captures the form as a profile. Blank ports are allowed.
func (u *ui) formProfile(name string) (profile.Profile, error) {
	var problems []string
	port := func(label string, e *widget.Entry) int {
		if strings.TrimSpace(e.Text) == "" {
			return 0
		}
		p, err := tunnel.ParsePort(e.Text)
		if err != nil {
			problems = append(problems, label+": "+err.Error())
		}
		return p
	}
	p := profile.Profile{
		Name:      name,
		SSHHost:   strings.TrimSpace(u.sshHost.Text),
		SSHPort:   port("SSH server port", u.sshPort),
		User:      strings.TrimSpace(u.user.Text),
		Auth:      u.auth(),
		KeyPath:   strings.TrimSpace(u.keyPath.Text),
		LocalPort: port("Local port", u.localPort),
		DestHost:  strings.TrimSpace(u.destHost.Text),
		DestPort:  port("Destination port", u.destPort),
	}
	if len(problems) > 0 {
		return p, errors.New(strings.Join(problems, "\n"))
	}
	return p, nil
}

func (u *ui) saveProfile() {
	name := widget.NewEntry()
	name.SetPlaceHolder("e.g. prod database")
	name.SetText(u.profileSel.Selected)
	d := dialog.NewForm("Save profile", "Save", "Cancel",
		[]*widget.FormItem{widget.NewFormItem("Name", name)},
		func(ok bool) {
			if !ok {
				return
			}
			p, err := u.formProfile(strings.TrimSpace(name.Text))
			if err != nil {
				dialog.ShowError(err, u.win)
				return
			}
			save := func() {
				if err := u.store.Put(p); err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.store.Last = p.Name
				if u.writeProfiles() {
					u.logf("saved profile %q (passwords and passphrases are never saved)", p.Name)
				}
				u.profileSel.SetOptions(u.store.Names())
				u.profileSel.SetSelected(p.Name)
			}
			if _, exists := u.store.Get(p.Name); exists && p.Name != u.profileSel.Selected {
				dialog.ShowConfirm("Replace profile?",
					fmt.Sprintf("A profile called %q already exists. Replace it?", p.Name),
					func(yes bool) {
						if yes {
							save()
						}
					}, u.win)
				return
			}
			save()
		}, u.win)
	name.OnSubmitted = func(string) { d.Submit() }
	d.Resize(fyne.NewSize(400, d.MinSize().Height))
	d.Show()
	u.win.Canvas().Focus(name)
}

func (u *ui) deleteProfile() {
	name := u.profileSel.Selected
	if name == "" {
		return
	}
	dialog.ShowConfirm("Delete profile?", fmt.Sprintf("Delete the profile %q?", name), func(yes bool) {
		if !yes {
			return
		}
		u.store.Delete(name)
		if u.writeProfiles() {
			u.logf("deleted profile %q", name)
		}
		u.profileSel.ClearSelected()
		u.profileSel.SetOptions(u.store.Names())
		u.refreshProfileButtons()
	}, u.win)
}

// writeProfiles saves the store, reporting failures. It reports success.
func (u *ui) writeProfiles() bool {
	if err := u.store.Save(u.profilePath); err != nil {
		u.logf("%v", err)
		dialog.ShowError(err, u.win)
		return false
	}
	return true
}

func entry(placeholder, text string) *widget.Entry {
	e := widget.NewEntry()
	e.SetPlaceHolder(placeholder)
	e.SetText(text)
	return e
}

func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (u *ui) pickKey() {
	d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil || r == nil {
			return
		}
		r.Close()
		u.keyPath.SetText(r.URI().Path())
	}, u.win)
	if home, err := os.UserHomeDir(); err == nil {
		if l, err := storage.ListerForURI(storage.NewFileURI(filepath.Join(home, ".ssh"))); err == nil {
			d.SetLocation(l)
		}
	}
	d.Resize(fyne.NewSize(700, 500))
	d.Show()
}

// setState updates widgets for s. Call on the UI goroutine.
func (u *ui) setState(s state, status, addr string) {
	u.state = s
	u.status.SetText(status)
	u.localAddr.SetText(addr)
	inputs := []fyne.Disableable{u.sshHost, u.sshPort, u.user, u.authMode, u.keyPath, u.password, u.localPort, u.destHost, u.destPort, u.browse}
	for _, w := range inputs {
		setEnabled(w, s == stateIdle)
	}
	if u.profileSel != nil {
		u.refreshProfileButtons()
	}
	switch s {
	case stateIdle:
		u.startBtn.Enable()
		u.startBtn.SetText("Start Forwarding")
		u.stopBtn.Disable()
		u.stopBtn.SetText("Stop Forwarding")
	case stateConnecting:
		u.startBtn.Disable()
		u.startBtn.SetText("Connecting…")
		u.stopBtn.Enable()
		u.stopBtn.SetText("Cancel")
	case stateConnected:
		u.startBtn.Disable()
		u.startBtn.SetText("Start Forwarding")
		u.stopBtn.Enable()
		u.stopBtn.SetText("Stop Forwarding")
	}
}

// logf appends a line to the log view. Safe to call from any goroutine.
func (u *ui) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...)
	fyne.Do(func() {
		u.logLines = append(u.logLines, line)
		if len(u.logLines) > maxLogLines {
			u.logLines = u.logLines[len(u.logLines)-maxLogLines:]
		}
		u.logText.SetText(strings.Join(u.logLines, "\n"))
		u.logScroll.ScrollToBottom()
	})
}

// formConfig validates the form and builds a tunnel config (without the
// signer or host key callback, which need the network or user prompts).
// keyPath is empty unless private key authentication is selected.
func (u *ui) formConfig() (tunnel.Config, string, error) {
	var cfg tunnel.Config
	var problems []string
	need := func(name string, e *widget.Entry) string {
		v := strings.TrimSpace(e.Text)
		if v == "" {
			problems = append(problems, name+" is required")
		}
		return v
	}
	port := func(name string, e *widget.Entry) int {
		p, err := tunnel.ParsePort(e.Text)
		if err != nil {
			problems = append(problems, name+": "+err.Error())
		}
		return p
	}
	cfg.SSHHost = need("SSH server host", u.sshHost)
	cfg.SSHPort = port("SSH server port", u.sshPort)
	cfg.User = need("SSH username", u.user)
	var keyPath string
	switch u.auth() {
	case profile.AuthPassword:
		if u.password.Text == "" {
			problems = append(problems, "Password is required")
		}
		cfg.Password = u.password.Text
	case profile.AuthAgent:
		cfg.UseAgent = true
	default:
		keyPath = need("Private key file", u.keyPath)
	}
	cfg.LocalPort = port("Local port", u.localPort)
	cfg.DestHost = need("Destination host", u.destHost)
	cfg.DestPort = port("Destination port", u.destPort)
	if len(problems) > 0 {
		return cfg, "", errors.New(strings.Join(problems, "\n"))
	}
	return cfg, keyPath, nil
}

func (u *ui) start() {
	if u.state != stateIdle {
		return
	}
	cfg, keyPath, err := u.formConfig()
	if err != nil {
		dialog.ShowError(err, u.win)
		return
	}
	cfg.Logf = u.logf

	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.setState(stateConnecting, "Connecting…", "")
	u.logf("connecting to %s@%s:%d", cfg.User, cfg.SSHHost, cfg.SSHPort)

	go func() {
		tun, err := u.connect(ctx, cfg, keyPath)
		fyne.Do(func() {
			cancel()
			if u.cancel == nil { // window closed or cancelled meanwhile
				if tun != nil {
					go tun.Stop()
				}
				return
			}
			u.cancel = nil
			if err != nil {
				msg := "Failed: " + err.Error()
				if errors.Is(err, context.Canceled) {
					msg = "Cancelled"
				} else {
					u.logf("%v", err)
					dialog.ShowError(err, u.win)
				}
				u.setState(stateIdle, msg, "")
				return
			}
			u.tun = tun
			u.setState(stateConnected, "Connected", "Forwarding on "+tun.LocalAddr())
			go u.watch(tun)
		})
	}()
}

// connect runs off the UI goroutine: loads the key unless a password is
// used, sets up host key checking and starts the tunnel.
func (u *ui) connect(ctx context.Context, cfg tunnel.Config, keyPath string) (*tunnel.Tunnel, error) {
	if keyPath != "" {
		signer, err := u.loadKey(keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Signer = signer
	}

	khPath, err := tunnel.DefaultKnownHostsPath()
	if err != nil {
		return nil, fmt.Errorf("could not locate your home directory for known_hosts: %w", err)
	}
	cfg.HostKeyCallback, cfg.HostKeyAlgorithms, err = tunnel.NewHostKeyCallback(khPath, cfg.SSHHost, cfg.SSHPort, u.confirmHostKey)
	if err != nil {
		return nil, err
	}
	return tunnel.Start(ctx, cfg)
}

// loadKey reads the private key, prompting for a passphrase if needed.
func (u *ui) loadKey(keyPath string) (ssh.Signer, error) {
	signer, err := tunnel.LoadSigner(keyPath, nil)
	for errors.Is(err, tunnel.ErrPassphraseRequired) || errors.Is(err, tunnel.ErrWrongPassphrase) {
		msg := "This private key is encrypted. Enter its passphrase (it will not be saved)."
		if errors.Is(err, tunnel.ErrWrongPassphrase) {
			msg = "Incorrect passphrase. Please try again."
		}
		pass, ok := u.askPassphrase(msg)
		if !ok {
			return nil, context.Canceled
		}
		signer, err = tunnel.LoadSigner(keyPath, pass)
		clear(pass)
	}
	return signer, err
}

// askPassphrase shows a modal prompt and blocks until it is answered.
func (u *ui) askPassphrase(msg string) ([]byte, bool) {
	ch := make(chan []byte, 1)
	fyne.Do(func() {
		pw := widget.NewPasswordEntry()
		label := widget.NewLabel(msg)
		label.Wrapping = fyne.TextWrapWord
		d := dialog.NewForm("Key passphrase", "Unlock", "Cancel",
			[]*widget.FormItem{widget.NewFormItem("", label), widget.NewFormItem("Passphrase", pw)},
			func(ok bool) {
				if ok {
					ch <- []byte(pw.Text)
				} else {
					ch <- nil
				}
				pw.SetText("")
			}, u.win)
		pw.OnSubmitted = func(string) { d.Submit() }
		d.Resize(fyne.NewSize(420, d.MinSize().Height))
		d.Show()
		u.win.Canvas().Focus(pw)
	})
	p := <-ch
	return p, p != nil
}

// confirmHostKey asks the user whether to trust a first-seen host key.
func (u *ui) confirmHostKey(host, keyType, fingerprint string) bool {
	ch := make(chan bool, 1)
	fyne.Do(func() {
		msg := widget.NewLabel(fmt.Sprintf(
			"The authenticity of host %s can't be established.\n\n"+
				"%s key fingerprint:\n%s\n\n"+
				"Only continue if this matches the fingerprint you expect for this server. "+
				"If you trust it, it will be saved to your known_hosts file.",
			host, keyType, fingerprint))
		msg.Wrapping = fyne.TextWrapWord
		d := dialog.NewCustomConfirm("Unknown SSH server", "Trust and connect", "Cancel", msg,
			func(ok bool) { ch <- ok }, u.win)
		d.Resize(fyne.NewSize(480, 300))
		d.Show()
	})
	ok := <-ch
	if ok {
		u.logf("trusted new host key for %s (%s)", host, fingerprint)
	}
	return ok
}

// watch reports an unexpected end of the tunnel.
func (u *ui) watch(tun *tunnel.Tunnel) {
	<-tun.Done()
	err := tun.Err()
	fyne.Do(func() {
		if u.tun != tun {
			return
		}
		u.tun = nil
		if err != nil {
			u.setState(stateIdle, "Disconnected: "+err.Error(), "")
			dialog.ShowError(err, u.win)
		} else {
			u.setState(stateIdle, "Not connected", "")
		}
	})
}

func (u *ui) stop() {
	switch u.state {
	case stateConnecting:
		if u.cancel != nil {
			u.cancel()
		}
	case stateConnected:
		tun := u.tun
		u.tun = nil
		u.stopBtn.Disable()
		u.status.SetText("Stopping…")
		go func() {
			tun.Stop()
			u.logf("forwarding stopped")
			fyne.Do(func() { u.setState(stateIdle, "Not connected", "") })
		}()
	}
}

// shutdown runs when the window closes: tear everything down synchronously.
func (u *ui) shutdown() {
	if u.cancel != nil {
		u.cancel()
		u.cancel = nil
	}
	if u.tun != nil {
		u.tun.Stop()
		u.tun = nil
	}
}
