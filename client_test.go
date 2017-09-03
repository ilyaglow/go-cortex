package gocortex

import (
	"testing"

	gocortex "github.com/ilyaglow/go-cortex"
)

func TestCortexUnavailable(t *testing.T) {
	client := gocortex.NewClient("http://127.0.0.1:9900")
	_, err := client.ListAnalyzers("*")
	if err == nil {
		t.Error("Expected panic on host unavailability")
	}
}
