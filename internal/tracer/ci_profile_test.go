package tracer

import (
	"testing"
	"time"
)

func TestCIProfile(t *testing.T) {
	requireRoot(t)
	for _, capacity := range []uint32{0, 256} {
		for i := range 3 {
			start := time.Now()
			tr, err := New(Options{TraceSelf: true, MaxFlows: capacity, OwnerScanInterval: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			loaded := time.Now()
			_, err = tr.Collect()
			collected := time.Now()
			if closeErr := tr.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			closed := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("capacity=%d iteration=%d New=%v Collect=%v Close=%v", capacity, i, loaded.Sub(start), collected.Sub(loaded), closed.Sub(collected))
		}
	}
}
