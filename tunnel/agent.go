package tunnel

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrNoAgent means no ssh-agent is reachable.
var ErrNoAgent = errors.New("no ssh-agent is running (SSH_AUTH_SOCK is not set); start one and add your key with ssh-add, or choose another authentication method")

// openAgent connects to the ssh-agent at socket, or $SSH_AUTH_SOCK if socket
// is empty, and returns its keys. The caller must close the connection once
// authentication is finished.
func openAgent(socket string) (net.Conn, []ssh.Signer, error) {
	if socket == "" {
		socket = os.Getenv("SSH_AUTH_SOCK")
	}
	if socket == "" {
		return nil, nil, ErrNoAgent
	}
	conn, err := net.DialTimeout("unix", socket, dialTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to ssh-agent at %s: %w", socket, err)
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("could not list ssh-agent keys: %w", err)
	}
	if len(signers) == 0 {
		conn.Close()
		return nil, nil, errors.New("ssh-agent has no keys loaded; add one with ssh-add")
	}
	return conn, signers, nil
}
