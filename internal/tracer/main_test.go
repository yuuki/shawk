package tracer

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the tests of the package if goroutines that they started,
// such as the reader of the cgroup events of a Tracer, are still running at
// their end.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
