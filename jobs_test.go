package gocortex

import (
	"testing"
)

func TestListJobs(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")

	_, err := client.ListJobs()
	if err != nil {
		t.Error("Can't list jobs")
	}
}

func TestListFilteredJobs(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")

	jf := &JobsFilter{
		Analyzer: "MaxMind_GeoIP_3_0",
		DataType: "ip",
	}

	_, err := client.ListFilteredJobs(jf)
	if err != nil {
		t.Errorf("Can't list filtered jobs: %s", err.Error())
	}
}
