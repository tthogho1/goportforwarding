package tunnel

import (
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// startAgent serves an in-memory ssh-agent holding keys on a Unix socket.
func startAgent(t *testing.T, keys ...ed25519.PrivateKey) string {
	t.Helper()
	// Unix socket paths are limited to ~104 bytes on macOS, so avoid t.TempDir.
	dir, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")

	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("unix", sock)
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
			go func() { agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	return sock
}

func TestAgentAuth(t *testing.T) {
	f := newFixture(t)
	f.cfg.Signer = nil
	f.cfg.UseAgent = true

	// The right key, alongside an unrelated one.
	other, _ := newKeyPair(t)
	f.cfg.AgentSocket = startAgent(t, other, f.clientPriv)
	tun, err := Start(context.Background(), f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := roundTrip(tun.LocalAddr(), "hi")
	tun.Stop()
	if err != nil || got != "hi" {
		t.Fatalf("round trip: got %q, %v", got, err)
	}

	f.cfg.AgentSocket = startAgent(t, other)
	_, err = Start(context.Background(), f.cfg)
	if err == nil || !strings.Contains(err.Error(), "ssh-agent's keys") {
		t.Fatalf("wrong key: got %v", err)
	}

	f.cfg.AgentSocket = startAgent(t)
	_, err = Start(context.Background(), f.cfg)
	if err == nil || !strings.Contains(err.Error(), "no keys loaded") {
		t.Fatalf("empty agent: got %v", err)
	}

	f.cfg.AgentSocket = ""
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err = Start(context.Background(), f.cfg)
	if err != ErrNoAgent {
		t.Fatalf("no agent: got %v", err)
	}
}
