// Package profile saves named tunnel settings to a JSON file. It never stores
// secrets: passwords and key passphrases are always entered at connect time.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Authentication methods.
const (
	AuthKey      = "key"
	AuthAgent    = "agent"
	AuthPassword = "password"
)

// Profile is one saved set of form values. Ports are 0 when left blank.
type Profile struct {
	Name      string `json:"name"`
	SSHHost   string `json:"sshHost"`
	SSHPort   int    `json:"sshPort,omitempty"`
	User      string `json:"user"`
	Auth      string `json:"auth"`
	KeyPath   string `json:"keyPath,omitempty"`
	LocalPort int    `json:"localPort,omitempty"`
	DestHost  string `json:"destHost"`
	DestPort  int    `json:"destPort,omitempty"`
}

// Store is the contents of the profiles file.
type Store struct {
	// Last is the profile that was selected most recently.
	Last     string    `json:"last,omitempty"`
	Profiles []Profile `json:"profiles"`
}

// DefaultPath is profiles.json in the per-user config directory, e.g.
// ~/Library/Application Support/goportforwarding on macOS.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "goportforwarding", "profiles.json"), nil
}

// Load reads the store at path. A missing file is an empty store.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Store{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read profiles: %w", err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("could not read profiles file %s: %w", path, err)
	}
	return &s, nil
}

// Save writes the store to path atomically, readable only by the user.
func (s *Store) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("could not create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".profiles-*.json")
	if err != nil {
		return fmt.Errorf("could not save profiles: %w", err)
	}
	defer os.Remove(f.Name()) // no-op once renamed
	_, err = f.Write(append(data, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return fmt.Errorf("could not save profiles: %w", err)
	}
	return nil
}

// Names returns the profile names in display order.
func (s *Store) Names() []string {
	names := make([]string, len(s.Profiles))
	for i, p := range s.Profiles {
		names[i] = p.Name
	}
	return names
}

// Get returns the profile called name.
func (s *Store) Get(name string) (Profile, bool) {
	i := s.index(name)
	if i < 0 {
		return Profile{}, false
	}
	return s.Profiles[i], true
}

// Put adds p, replacing any profile with the same name, and keeps the list
// sorted by name.
func (s *Store) Put(p Profile) error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return errors.New("profile name is required")
	}
	if i := s.index(p.Name); i >= 0 {
		s.Profiles[i] = p
	} else {
		s.Profiles = append(s.Profiles, p)
	}
	slices.SortFunc(s.Profiles, func(a, b Profile) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return nil
}

// Delete removes the profile called name, if present.
func (s *Store) Delete(name string) {
	if i := s.index(name); i >= 0 {
		s.Profiles = slices.Delete(s.Profiles, i, i+1)
	}
	if s.Last == name {
		s.Last = ""
	}
}

func (s *Store) index(name string) int {
	return slices.IndexFunc(s.Profiles, func(p Profile) bool { return p.Name == name })
}
