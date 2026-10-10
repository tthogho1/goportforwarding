package tunnel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	// ErrPassphraseRequired means the private key is encrypted.
	ErrPassphraseRequired = errors.New("the private key is encrypted and needs a passphrase")
	// ErrWrongPassphrase means the passphrase did not decrypt the key.
	ErrWrongPassphrase = errors.New("incorrect passphrase for the private key")
	// ErrHostKeyRejected means the user declined to trust a new host key.
	ErrHostKeyRejected = errors.New("the SSH server's host key was not trusted, so the connection was cancelled")
)

// HostKeyMismatchError means the server presented a key different from the
// one recorded in known_hosts. This may indicate a man-in-the-middle attack.
type HostKeyMismatchError struct {
	Host           string
	Fingerprint    string
	KnownHostsFile string
	Known          []knownhosts.KnownKey
}

func (e *HostKeyMismatchError) Error() string {
	var lines []string
	for _, k := range e.Known {
		lines = append(lines, fmt.Sprintf("%s line %d", k.Filename, k.Line))
	}
	return fmt.Sprintf("WARNING: the host key for %s does not match the one recorded in %s (%s). "+
		"The server presented %s. This could mean someone is intercepting the connection, or the server's key was changed. "+
		"If you are sure the change is legitimate, remove the old entry and try again.",
		e.Host, e.KnownHostsFile, strings.Join(lines, ", "), e.Fingerprint)
}

// LoadSigner reads a private key file. If the key is encrypted and
// passphrase is empty it returns ErrPassphraseRequired.
func LoadSigner(path string, passphrase []byte) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}
	defer clear(data)

	var s ssh.Signer
	if len(passphrase) == 0 {
		s, err = ssh.ParsePrivateKey(data)
	} else {
		s, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return s, nil
	case errors.As(err, &missing):
		return nil, ErrPassphraseRequired
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrWrongPassphrase
	}
	return nil, fmt.Errorf("could not use the private key file (is it an OpenSSH private key?): %w", err)
}

// DefaultKnownHostsPath returns ~/.ssh/known_hosts, shared with OpenSSH.
func DefaultKnownHostsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "known_hosts"), nil
}

// ConfirmFunc asks the user whether to trust a host key seen for the first
// time. fingerprint is the SHA256 fingerprint as printed by ssh-keygen -l.
type ConfirmFunc func(host, keyType, fingerprint string) bool

// NewHostKeyCallback verifies host keys against the known_hosts file at path
// (created if missing). Unknown hosts are passed to confirm and, if accepted,
// appended to the file. Changed keys are always rejected.
//
// It also returns the host key algorithms already recorded for host:port, to
// be used as Config.HostKeyAlgorithms.
func NewHostKeyCallback(path, host string, port int, confirm ConfirmFunc) (ssh.HostKeyCallback, []string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("could not create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open known hosts file: %w", err)
	}
	f.Close()

	kh, err := knownhosts.New(path)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read known hosts file %s: %w", path, err)
	}

	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(hostname, remote, key)
		var ke *knownhosts.KeyError
		if err == nil || !errors.As(err, &ke) {
			return err
		}
		fp := ssh.FingerprintSHA256(key)
		if len(ke.Want) > 0 {
			return &HostKeyMismatchError{Host: hostname, Fingerprint: fp, KnownHostsFile: path, Known: ke.Want}
		}
		if confirm == nil || !confirm(hostname, key.Type(), fp) {
			return ErrHostKeyRejected
		}
		return appendKnownHost(path, hostname, key)
	}

	return cb, knownAlgorithms(kh, net.JoinHostPort(host, strconv.Itoa(port))), nil
}

// knownAlgorithms looks up the key types recorded for addr by checking a
// throwaway key and reading the expected keys from the resulting error.
func knownAlgorithms(kh ssh.HostKeyCallback, addr string) []string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if !errors.As(kh(addr, &net.TCPAddr{IP: net.IPv4zero}, probe), &ke) {
		return nil
	}
	var algos []string
	for _, k := range ke.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			algos = append(algos, t)
		}
	}
	return algos
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	existing, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read known hosts file: %w", err)
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		line = "\n" + line
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("could not update known hosts file: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("could not update known hosts file: %w", err)
	}
	return nil
}
