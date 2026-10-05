package gateway

import "testing"

// DO NOT MERGE: deliberately failing test to verify that the required
// `test` check blocks merging into main.
func TestCICanaryDeliberatelyFails(t *testing.T) {
	t.Fatal("deliberate failure: verifies the required test check blocks merging")
}
