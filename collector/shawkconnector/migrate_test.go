package shawkconnector

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// releasedMigrations are the SHA-256 of the migrations of releases. A
// database migrated by a release does not apply them again, so changing
// one would leave such databases without the change, and later migrations
// that depend on it would fail there: a change of the schema is a new
// migration.
var releasedMigrations = map[string]string{
	"0001_schema.sql": "d7ff26f7bdc01a04571347a77fb8267890d1ac8a36c1c03d31a77bb0295c31c3", // v0.8.0, v0.8.1
}

func TestReleasedMigrations(t *testing.T) {
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for i, m := range ms {
		if m.Version != i+1 {
			t.Errorf("migration %s has version %d, want %d: versions follow each other from 1", m.Name, m.Version, i+1)
		}
		want, ok := releasedMigrations[m.Name]
		if !ok {
			continue
		}
		found[m.Name] = true
		sum := sha256.Sum256([]byte(m.SQL))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s was released and changed since (SHA-256 %s); put the change in a new migration", m.Name, got)
		}
	}
	for name := range releasedMigrations {
		if !found[name] {
			t.Errorf("the released migration %s is missing", name)
		}
	}
}
