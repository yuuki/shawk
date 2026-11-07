package procinfo

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the tests of the package if goroutines that they started
// are still running at their end. The reader of the queued reads of a
// Resolver runs as long as the Resolver, which the agent keeps until it
// exits: it has no Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreTopFunction("github.com/yuuki/shawk/internal/procinfo.(*Resolver).readQueued"))
}
