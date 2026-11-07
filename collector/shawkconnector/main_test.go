package shawkconnector

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the tests of the package if goroutines that they started
// are still running at their end.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
