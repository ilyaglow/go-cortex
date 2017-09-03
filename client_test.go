package gocortex

import (
	"testing"
)

func TestCortexUnavailable(t *testing.T) {
	client := NewClient("http://127.0.0.1:9900")
	_, err := client.ListAnalyzers("*")
	if err == nil {
		t.Error("Expected panic on host unavailability")
	}
}
