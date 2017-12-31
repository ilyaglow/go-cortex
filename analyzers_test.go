package gocortex

import (
	"encoding/json"
	"log"
	"testing"
	"time"
)

var getAnalyzerResponse = []byte(`
{
  "name": "File_Info",
  "version": "1.0",
  "description": "Parse files in several formats such as OLE and OpenXML to detect VBA macros, extract their source code, generate useful information on PE, PDF files and much more.",
  "dataTypeList": [
    "file"
  ],
  "id": "File_Info_1_0"
}
`)

func TestListAnalyzers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListAnalyzers")
	}

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
	if testing.Short() {
		t.Skip("Skipping GetAnalyzer")
	}

	client := NewClient("http://127.0.0.1:9000")
	mm, err := client.GetAnalyzer("MaxMind_GeoIP_3_0")
	if err != nil {
		t.Error("Can't do query to get analyzers")
	}

	if mm.ID != "MaxMind_GeoIP_3_0" {
		t.Error("Wrong analyzer name")
	}
}

func TestRunAnalyzerAndGetJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping RunAnalyzer")
	}

	client := NewClient("http://127.0.0.1:9000")

	j := &Artifact{
		Data: "8.8.8.8",
		Attributes: ArtifactAttributes{
			DataType: "ip",
			TLP:      2,
		},
	}

	job, err := client.RunAnalyzer("MaxMind_GeoIP_3_0", j)
	if err != nil {
		t.Errorf("Can't run analyzer: %s", err.Error())
	}

	if job.Status != "InProgress" {
		t.Errorf("Job status is not InProgress: %s", job.Status)
	}

	time.Sleep(10000 * time.Millisecond)
	sjob, err := client.GetJob(job.ID)
	if err != nil {
		t.Errorf("Failed to get a job: %s", err.Error())
	}

	if sjob.Status != "Success" {
		t.Errorf("MaxMind analyzer has not succeded: %s", sjob.Status)
	}
}

func TestRunAnalyzerThenGetReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping RunAnalyzerThenGetReport")
	}

	client := NewClient("http://127.0.0.1:9000")

	j := &Artifact{
		Data: "8.8.8.8",
		Attributes: ArtifactAttributes{
			DataType: "ip",
			TLP:      2,
		},
	}

	_, err := client.RunAnalyzerThenGetReport("MaxMind_GeoIP_3_0", j, "30seconds")
	if err != nil {
		t.Error("Can't run analyzer and get report")
	}
}

func TestAnalyzeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping AnalyzeData")
	}

	client := NewClient("http://127.0.0.1:9000")

	j := &Artifact{
		Data: "8.8.8.8",
		Attributes: ArtifactAttributes{
			DataType: "ip",
			TLP:      3,
		},
	}

	messages, err := client.AnalyzeData(j, "1minute")
	if err != nil {
		t.Error("Can't analyze data")
	}
	for m := range messages {
		log.Printf("%s: %s", m.AnalyzerID, m.Status)

		status, err := client.DeleteJob(m.ID)
		if err != nil {
			t.Errorf("Can't delete a job: %s", err.Error())
		}

		if status != true {
			t.Error("Job has not been deleted")
		}
	}
}

func TestGetAnalyzersResponse(t *testing.T) {
	a := Analyzer{}

	if err := json.Unmarshal(getAnalyzerResponse, &a); err != nil {
		t.Error("Can't unmarshal predefined list analyzers response")
	}

	if a.ID != "File_Info_1_0" {
		t.Error("Wrong analyzer ID")
	}

	if a.Name != "File_Info" {
		t.Error("Wrong analyzer name")
	}

	if a.Description != "Parse files in several formats such as OLE and OpenXML to detect VBA macros, extract their source code, generate useful information on PE, PDF files and much more." {
		t.Error("Wrong analyzer description")
	}

	if a.Version != "1.0" {
		t.Error("Wrong analyzer version")
	}

	for _, dt := range a.DataTypeList {
		if dt != "file" {
			t.Error("Wrong analyzer datatype")
		}
	}
}
