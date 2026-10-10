// Package tunnel implements a single SSH local (-L) port-forwarding tunnel,
// equivalent to:
//
//	ssh -N -L 127.0.0.1:<local-port>:<dest-host>:<dest-port> user@ssh-host
//
// Connections accepted on the local listener are carried through the SSH
// server, which then dials <dest-host>:<dest-port> from its own network.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// DefaultBindAddr keeps the forwarded port reachable only from this computer.
	DefaultBindAddr = "127.0.0.1"

	dialTimeout       = 15 * time.Second
	keepAliveInterval = 30 * time.Second
	keepAliveTimeout  = 15 * time.Second
)

// Config describes one tunnel.
type Config struct {
	SSHHost string
	SSHPort int
	User    string
	// Exactly one of Signer (private key), Password or UseAgent
	// authenticates the user.
	Signer   ssh.Signer
	Password string
	UseAgent bool
	// AgentSocket overrides $SSH_AUTH_SOCK when UseAgent is set.
	AgentSocket string

	LocalPort int
	// BindAddr is the local listen address. Empty means DefaultBindAddr.
	BindAddr string

	DestHost string
	DestPort int

	// HostKeyCallback verifies the SSH server's host key. Required; see
	// NewHostKeyCallback. Never use ssh.InsecureIgnoreHostKey here.
	HostKeyCallback ssh.HostKeyCallback
	// HostKeyAlgorithms optionally restricts negotiated host key types, so a
	// server is verified against the key type already in known_hosts.
	HostKeyAlgorithms []string

	// Logf receives diagnostic messages. It is never passed key material.
	Logf func(format string, args ...any)
}

// ParsePort parses a TCP port number in the range 1-65535.
func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%q is not a valid port (must be a whole number from 1 to 65535)", s)
	}
	return p, nil
}

// Validate checks that all required fields are present and in range.
func (c *Config) Validate() error {
	var problems []string
	if strings.TrimSpace(c.SSHHost) == "" {
		problems = append(problems, "SSH server host is required")
	}
	if strings.TrimSpace(c.User) == "" {
		problems = append(problems, "SSH username is required")
	}
	methods := 0
	for _, set := range []bool{c.Signer != nil, c.Password != "", c.UseAgent} {
		if set {
			methods++
		}
	}
	if methods != 1 {
		problems = append(problems, "exactly one of a private key, ssh-agent or a password is required")
	}
	if strings.TrimSpace(c.DestHost) == "" {
		problems = append(problems, "destination host is required")
	}
	for name, p := range map[string]int{"SSH server port": c.SSHPort, "local port": c.LocalPort, "destination port": c.DestPort} {
		if p < 1 || p > 65535 {
			problems = append(problems, fmt.Sprintf("%s must be from 1 to 65535", name))
		}
	}
	if c.HostKeyCallback == nil {
		problems = append(problems, "host key verification is not configured")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Tunnel is an active forwarding session. Create one with Start.
type Tunnel struct {
	cfg      Config
	dest     string
	client   *ssh.Client
	listener net.Listener

	closing   chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	err       error
	wg        sync.WaitGroup

	mu     sync.Mutex
	closed bool
	active map[net.Conn]struct{}
}

// Start opens the local listener, connects and authenticates to the SSH
// server, checks that the destination is reachable through it, and then
// begins forwarding. Cancelling ctx aborts a start that is still in progress.
func Start(ctx context.Context, cfg Config) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = DefaultBindAddr
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}

	// Bind first: a port that is already in use is reported without any
	// network round trip.
	localAddr := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.LocalPort))
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("could not open local port %s (is another program already using it?): %w", localAddr, err)
	}

	client, err := dialSSH(ctx, &cfg)
	if err != nil {
		ln.Close()
		return nil, err
	}

	dest := net.JoinHostPort(cfg.DestHost, strconv.Itoa(cfg.DestPort))
	probeCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	probe, err := dialRemote(probeCtx, client, dest)
	cancel()
	if err != nil {
		client.Close()
		ln.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("destination %s is unreachable from the SSH server: %w", dest, err)
	}
	probe.Close()

	t := &Tunnel{
		cfg:      cfg,
		dest:     dest,
		client:   client,
		listener: ln,
		closing:  make(chan struct{}),
		done:     make(chan struct{}),
		active:   make(map[net.Conn]struct{}),
	}
	t.wg.Add(3)
	go t.acceptLoop()
	go t.keepAlive()
	go func() {
		defer t.wg.Done()
		err := client.Wait()
		if err == nil || errors.Is(err, io.EOF) {
			err = errors.New("the server closed the connection")
		}
		t.shutdown(fmt.Errorf("SSH connection lost: %w", err))
	}()

	cfg.Logf("forwarding %s -> %s (via %s@%s)", ln.Addr(), dest, cfg.User, net.JoinHostPort(cfg.SSHHost, strconv.Itoa(cfg.SSHPort)))
	return t, nil
}

// LocalAddr is the address local applications should connect to.
func (t *Tunnel) LocalAddr() string { return t.listener.Addr().String() }

// Done is closed once the tunnel has fully shut down.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// Err reports why the tunnel ended. It is nil if Stop was called first, and
// only meaningful after Done is closed.
func (t *Tunnel) Err() error {
	<-t.done
	return t.err
}

// Stop closes the listener, all forwarded connections and the SSH session,
// and waits for everything to finish.
func (t *Tunnel) Stop() {
	t.shutdown(nil)
	<-t.done
}

func (t *Tunnel) shutdown(err error) {
	t.closeOnce.Do(func() {
		t.err = err
		if err != nil {
			t.cfg.Logf("tunnel stopped: %v", err)
		}
		close(t.closing)
		t.listener.Close()
		t.client.Close()
		t.mu.Lock()
		t.closed = true
		for c := range t.active {
			c.Close()
		}
		t.mu.Unlock()
		go func() {
			t.wg.Wait()
			close(t.done)
		}()
	})
}

func (t *Tunnel) acceptLoop() {
	defer t.wg.Done()
	for {
		c, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.closing:
			default:
				t.shutdown(fmt.Errorf("local listener failed: %w", err))
			}
			return
		}
		t.wg.Add(1)
		go t.forward(c)
	}
}

func (t *Tunnel) forward(local net.Conn) {
	defer t.wg.Done()
	if !t.track(local) {
		local.Close()
		return
	}
	defer t.untrack(local)

	remote, err := t.client.Dial("tcp", t.dest)
	if err != nil {
		t.cfg.Logf("connection from %s rejected: destination %s unreachable: %v", local.RemoteAddr(), t.dest, err)
		local.Close()
		return
	}
	t.cfg.Logf("connection from %s opened", local.RemoteAddr())
	pipe(local, remote)
	t.cfg.Logf("connection from %s closed", local.RemoteAddr())
}

func (t *Tunnel) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.active[c] = struct{}{}
	return true
}

func (t *Tunnel) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.active, c)
	t.mu.Unlock()
}

func (t *Tunnel) keepAlive() {
	defer t.wg.Done()
	tick := time.NewTicker(keepAliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-t.closing:
			return
		case <-tick.C:
		}
		errc := make(chan error, 1)
		go func() {
			_, _, err := t.client.SendRequest("keepalive@openssh.com", true, nil)
			errc <- err
		}()
		select {
		case err := <-errc:
			if err != nil {
				t.shutdown(fmt.Errorf("SSH keepalive failed: %w", err))
				return
			}
		case <-time.After(keepAliveTimeout):
			t.shutdown(errors.New("the SSH server stopped responding (keepalive timed out)"))
			return
		case <-t.closing:
			return
		}
	}
}

// pipe copies data both ways until both directions finish, half-closing each
// side as its input ends.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// authMethods returns the key, the ssh-agent's keys, or the password offered
// both as plain password auth and as keyboard-interactive (which many servers
// use instead). Call cleanup once the handshake is over.
func authMethods(cfg *Config) (methods []ssh.AuthMethod, cleanup func(), err error) {
	cleanup = func() {}
	switch {
	case cfg.Signer != nil:
		return []ssh.AuthMethod{ssh.PublicKeys(cfg.Signer)}, cleanup, nil
	case cfg.UseAgent:
		conn, signers, err := openAgent(cfg.AgentSocket)
		if err != nil {
			return nil, cleanup, err
		}
		cfg.Logf("using %d key(s) from ssh-agent", len(signers))
		return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, func() { conn.Close() }, nil
	}
	answer := func(_, _ string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range questions {
			// Only answer hidden prompts; echoed ones are not asking for a password.
			if !echos[i] {
				answers[i] = cfg.Password
			}
		}
		return answers, nil
	}
	return []ssh.AuthMethod{
		ssh.Password(cfg.Password),
		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(answer), 1),
	}, cleanup, nil
}

func dialSSH(ctx context.Context, cfg *Config) (*ssh.Client, error) {
	auth, cleanup, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	addr := net.JoinHostPort(cfg.SSHHost, strconv.Itoa(cfg.SSHPort))
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isTimeout(err) {
			return nil, fmt.Errorf("timed out connecting to SSH server %s", addr)
		}
		return nil, fmt.Errorf("could not connect to SSH server %s: %w", addr, err)
	}

	// Bound the handshake, but suspend the deadline while the host key
	// callback runs: it may be waiting for the user to answer a prompt.
	conn.SetDeadline(time.Now().Add(dialTimeout))
	verify := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		conn.SetDeadline(time.Time{})
		defer conn.SetDeadline(time.Now().Add(dialTimeout))
		return cfg.HostKeyCallback(hostname, remote, key)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              auth,
		HostKeyCallback:   verify,
		HostKeyAlgorithms: cfg.HostKeyAlgorithms,
		Timeout:           dialTimeout,
	})
	if !stop() {
		if c != nil {
			c.Close()
		}
		conn.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		conn.Close()
		var mismatch *HostKeyMismatchError
		switch {
		case errors.As(err, &mismatch), errors.Is(err, ErrHostKeyRejected):
			return nil, unwrapHandshake(err)
		case strings.Contains(err.Error(), "unable to authenticate"):
			switch {
			case cfg.UseAgent:
				return nil, fmt.Errorf("authentication failed: the server did not accept any of the ssh-agent's keys for user %q", cfg.User)
			case cfg.Signer == nil:
				return nil, fmt.Errorf("authentication failed: the server did not accept the password for user %q (or it does not allow password login)", cfg.User)
			}
			return nil, fmt.Errorf("authentication failed: the server did not accept this private key for user %q", cfg.User)
		case isTimeout(err):
			return nil, fmt.Errorf("timed out waiting for SSH server %s to respond", addr)
		}
		return nil, fmt.Errorf("SSH connection to %s failed: %w", addr, err)
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// unwrapHandshake strips the "ssh: handshake failed:" prefix from our own
// host-key errors so the user sees the plain explanation.
func unwrapHandshake(err error) error {
	var mismatch *HostKeyMismatchError
	if errors.As(err, &mismatch) {
		return mismatch
	}
	return ErrHostKeyRejected
}

// dialRemote opens a channel to addr through the SSH server, honouring ctx.
func dialRemote(ctx context.Context, client *ssh.Client, addr string) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := client.Dial("tcp", addr)
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
