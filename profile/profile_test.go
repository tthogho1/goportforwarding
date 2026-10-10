package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "profiles.json")

	s, err := Load(path)
	if err != nil || len(s.Profiles) != 0 {
		t.Fatalf("missing file: got %+v, %v", s, err)
	}

	db := Profile{Name: "prod db", SSHHost: "bastion", SSHPort: 22, User: "alice", Auth: AuthKey,
		KeyPath: "/k", LocalPort: 15432, DestHost: "db", DestPort: 5432}
	for _, p := range []Profile{db, {Name: "Cache", Auth: AuthAgent}, {Name: "  ", Auth: AuthKey}} {
		err := s.Put(p)
		if (err != nil) != (strings.TrimSpace(p.Name) == "") {
			t.Fatalf("Put(%q) = %v", p.Name, err)
		}
	}
	s.Last = "prod db"
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v, %v", fi.Mode(), err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Cache", "prod db"}; !reflect.DeepEqual(got.Names(), want) {
		t.Fatalf("names = %v, want %v", got.Names(), want)
	}
	if p, ok := got.Get("prod db"); !ok || p != db || got.Last != "prod db" {
		t.Fatalf("Get = %+v %v, last %q", p, ok, got.Last)
	}

	// Saving under an existing name replaces it.
	db.DestPort = 6543
	got.Put(db)
	if p, _ := got.Get("prod db"); p.DestPort != 6543 || len(got.Profiles) != 2 {
		t.Fatalf("replace: %+v", got.Profiles)
	}

	got.Delete("prod db")
	if _, ok := got.Get("prod db"); ok || got.Last != "" {
		t.Fatalf("delete: %+v", got)
	}
}

func TestCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}
