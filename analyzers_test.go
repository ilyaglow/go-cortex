package gocortex

import (
	"testing"
)

func TestListAnalyzers(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")
	a, err := client.ListAnalyzers("*")
	if err != nil {
		t.Errorf("Can't list analyzers: %s", err.Error())
	}

	if len(a) < 1 {
		t.Error("No analyzers")
	}

	ipAnalyzers, err := client.ListAnalyzers("ip")
	if err != nil {
		t.Errorf("Can't list analyzers by ip filter: %s", err.Error())
	}

	if len(ipAnalyzers) < 1 {
		t.Error("No ip analyzers")
	}
}

func TestGetAnalyzer(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")
	mm, err := client.GetAnalyzer("MaxMind_GeoIP_3_0")
	if err != nil {
		t.Error("Can't do query to get analyzers")
	}

	if mm.ID != "MaxMind_GeoIP_3_0" {
		t.Error("Wrong analyzer name")
	}
}

func TestRunAnalyzer(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")

	j := &JobBody{
		Data: "8.8.8.8",
		Attributes: ArtifactAttributes{
			DataType: "ip",
			TLP:      2,
		},
	}

	_, err := client.RunAnalyzer("MaxMind_GeoIP_3_0", j)
	if err != nil {
		t.Error("Can't run analyzer")
	}
}
