package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) ssh.Signer {
	_, s := newKeyPair(t)
	return s
}

func newKeyPair(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, s
}

// startSSHServer runs a minimal SSH server that accepts clientKey and serves
// direct-tcpip (local forwarding) channels.
func startSSHServer(t *testing.T, hostKey ssh.Signer, clientKey ssh.PublicKey) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	return serveSSHConfig(t, hostKey, cfg)
}

const testPassword = "correct horse"

// startPasswordServer runs a server that accepts testPassword, via password
// auth and/or keyboard-interactive auth.
func startPasswordServer(t *testing.T, hostKey ssh.Signer, password, interactive bool) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{}
	if password {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == testPassword {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	}
	if interactive {
		cfg.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ask("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(ans) == 1 && ans[0] == testPassword {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	}
	return serveSSHConfig(t, hostKey, cfg)
}

func serveSSHConfig(t *testing.T, hostKey ssh.Signer, cfg *ssh.ServerConfig) (host string, port int) {
	t.Helper()
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(c, cfg)
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func serveSSH(c net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		var p struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if err := ssh.Unmarshal(nc.ExtraData(), &p); err != nil {
			nc.Reject(ssh.Prohibited, "bad payload")
			continue
		}
		target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
		if err != nil {
			nc.Reject(ssh.ConnectionFailed, err.Error())
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			target.Close()
			continue
		}
		go ssh.DiscardRequests(chReqs)
		go func() {
			go func() { io.Copy(target, ch); target.(*net.TCPConn).CloseWrite() }()
			io.Copy(ch, target)
			ch.CloseWrite()
		}()
	}
}

func startEcho(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type fixture struct {
	hostKey, clientKey ssh.Signer
	clientPriv         ed25519.PrivateKey
	cfg                Config
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{hostKey: newSigner(t)}
	f.clientPriv, f.clientKey = newKeyPair(t)
	host, port := startSSHServer(t, f.hostKey, f.clientKey.PublicKey())
	f.cfg = Config{
		SSHHost: host, SSHPort: port, User: "alice", Signer: f.clientKey,
		LocalPort: freePort(t), DestHost: "127.0.0.1", DestPort: startEcho(t),
		HostKeyCallback: ssh.FixedHostKey(f.hostKey.PublicKey()),
		Logf:            t.Logf,
	}
	return f
}

func roundTrip(addr, msg string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	return string(b), err
}

func TestForwardAndStop(t *testing.T) {
	f := newFixture(t)
	tun, err := Start(context.Background(), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tun.LocalAddr(), "127.0.0.1:") {
		t.Fatalf("listener should be loopback-only, got %s", tun.LocalAddr())
	}
	for i := range 3 {
		msg := "hello " + strconv.Itoa(i)
		got, err := roundTrip(tun.LocalAddr(), msg)
		if err != nil || got != msg {
			t.Fatalf("round trip: got %q, %v", got, err)
		}
	}

	tun.Stop()
	if err := tun.Err(); err != nil {
		t.Fatalf("Err after Stop = %v, want nil", err)
	}
	if _, err := net.DialTimeout("tcp", tun.LocalAddr(), time.Second); err == nil {
		t.Fatal("local listener still accepting after Stop")
	}
}

func TestLocalPortInUse(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f.cfg.LocalPort = ln.Addr().(*net.TCPAddr).Port
	_, err = Start(context.Background(), f.cfg)
	if err == nil || !strings.Contains(err.Error(), "already using it") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthFailure(t *testing.T) {
	f := newFixture(t)
	f.cfg.Signer = newSigner(t)
	_, err := Start(context.Background(), f.cfg)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("got %v", err)
	}
}

func TestPasswordAuth(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		password, interactive bool
	}{
		{"password", true, false},
		{"keyboard-interactive", false, true},
		{"both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.SSHHost, f.cfg.SSHPort = startPasswordServer(t, f.hostKey, tc.password, tc.interactive)
			f.cfg.Signer = nil
			f.cfg.Password = testPassword
			tun, err := Start(context.Background(), f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			got, err := roundTrip(tun.LocalAddr(), "hi")
			tun.Stop()
			if err != nil || got != "hi" {
				t.Fatalf("round trip: got %q, %v", got, err)
			}

			f.cfg.Password = "wrong"
			_, err = Start(context.Background(), f.cfg)
			if err == nil || !strings.Contains(err.Error(), "did not accept the password") {
				t.Fatalf("wrong password: got %v", err)
			}
		})
	}
}

func TestAuthRequiresKeyOrPassword(t *testing.T) {
	f := newFixture(t)
	f.cfg.Password = testPassword // both set
	if err := f.cfg.Validate(); err == nil {
		t.Fatal("expected error with both key and password")
	}
	f.cfg.Signer, f.cfg.Password = nil, ""
	if err := f.cfg.Validate(); err == nil {
		t.Fatal("expected error with neither key nor password")
	}
}

func TestDestinationUnreachable(t *testing.T) {
	f := newFixture(t)
	f.cfg.DestPort = freePort(t)
	_, err := Start(context.Background(), f.cfg)
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v", err)
	}
	// The local port must be released after a failed start.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(f.cfg.LocalPort)))
	if err != nil {
		t.Fatalf("local port not released: %v", err)
	}
	ln.Close()
}

func TestSSHServerGoesAway(t *testing.T) {
	f := newFixture(t)
	tun, err := Start(context.Background(), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	tun.client.Conn.Close() // simulate a dropped network connection
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not notice the lost connection")
	}
	if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("got %v", err)
	}
}

func TestKnownHosts(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "ssh", "known_hosts")

	asked := 0
	trust := func(answer bool) ConfirmFunc {
		return func(host, typ, fp string) bool {
			asked++
			if fp != ssh.FingerprintSHA256(f.hostKey.PublicKey()) {
				t.Errorf("unexpected fingerprint %s", fp)
			}
			return answer
		}
	}
	start := func(confirm ConfirmFunc) error {
		cb, algos, err := NewHostKeyCallback(path, f.cfg.SSHHost, f.cfg.SSHPort, confirm)
		if err != nil {
			t.Fatal(err)
		}
		cfg := f.cfg
		cfg.HostKeyCallback, cfg.HostKeyAlgorithms = cb, algos
		tun, err := Start(context.Background(), cfg)
		if err == nil {
			tun.Stop()
		}
		return err
	}

	// Declined: not connected, nothing recorded.
	if err := start(trust(false)); !errors.Is(err, ErrHostKeyRejected) {
		t.Fatalf("declined: got %v", err)
	}
	// Accepted: recorded in known_hosts.
	if err := start(trust(true)); err != nil {
		t.Fatalf("accepted: %v", err)
	}
	// Known: no prompt.
	if err := start(trust(false)); err != nil {
		t.Fatalf("known host: %v", err)
	}
	if asked != 2 {
		t.Fatalf("prompted %d times, want 2", asked)
	}
	if _, algos, _ := NewHostKeyCallback(path, f.cfg.SSHHost, f.cfg.SSHPort, nil); len(algos) != 1 || algos[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("known algorithms = %v", algos)
	}

	// A different server on the same address: rejected as a mismatch.
	data, _ := os.ReadFile(path)
	other := newSigner(t)
	line := strings.Replace(string(data),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.hostKey.PublicKey()))),
		strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey()))), 1)
	os.WriteFile(path, []byte(line), 0o600)
	var mismatch *HostKeyMismatchError
	if err := start(trust(true)); !errors.As(err, &mismatch) {
		t.Fatalf("mismatch: got %v", err)
	}
}

func TestLoadSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()

	plainBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, pem.EncodeToMemory(plainBlock), 0o600)
	if _, err := LoadSigner(plain, nil); err != nil {
		t.Fatalf("plain key: %v", err)
	}

	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "enc")
	os.WriteFile(enc, pem.EncodeToMemory(encBlock), 0o600)
	if _, err := LoadSigner(enc, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("no passphrase: got %v", err)
	}
	if _, err := LoadSigner(enc, []byte("wrong")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: got %v", err)
	}
	if _, err := LoadSigner(enc, []byte("secret")); err != nil {
		t.Fatalf("right passphrase: %v", err)
	}
}

func TestParsePort(t *testing.T) {
	for _, s := range []string{"0", "65536", "-1", "abc", "", "1.5"} {
		if _, err := ParsePort(s); err == nil {
			t.Errorf("ParsePort(%q) accepted", s)
		}
	}
	if p, err := ParsePort(" 22 "); err != nil || p != 22 {
		t.Errorf("ParsePort(22) = %d, %v", p, err)
	}
}
