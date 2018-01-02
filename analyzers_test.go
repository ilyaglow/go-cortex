package cortex

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

var a = &Artifact{
	Data: "8.8.8.8",
	Attributes: ArtifactAttributes{
		DataType: "ip",
		TLP:      2,
	},
}

func TestListAnalyzersFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.ListAnalyzers("*")
	if v != nil && nerr == nil {
		t.Error("ListAnalyzers should have failed")
	}
}

func TestListAnalyzers(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListAnalyzers with a valid Cortex server")
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

func TestGetAnalyzerFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.GetAnalyzer("MaxMind_GeoIP_3_0")
	if v != nil && nerr == nil {
		t.Error("GetAnalyzer should have failed")
	}
}

func TestGetAnalyzer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping GetAnalyzer with a valid Cortex server")
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

func TestRunAnalyzerAndGetJobFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.RunAnalyzer("MaxMind_GeoIP_3_0", a)
	if v != nil && nerr == nil {
		t.Error("RunAnalyzer should have failed")
	}

	job, gerr := nonvalidClient.GetJob("nonexistentid")
	if job != nil && gerr == nil {
		t.Error("GetJob should have failed")
	}

}

func TestRunAnalyzerAndGetJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping RunAnalyzerAndGetJob with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")

	job, err := client.RunAnalyzer("MaxMind_GeoIP_3_0", a)
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

func TestRunAnalyzerThenGetReportFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")
	job, nerr := nonvalidClient.RunAnalyzerThenGetReport("MaxMind_GeoIP_3_0", a, "30seconds")
	if job != nil && nerr == nil {
		t.Error("RunAnalyzerTheGetReport should have failed")
	}
}

func TestRunAnalyzerThenGetReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping RunAnalyzerThenGetReport")
	}

	client := NewClient("http://127.0.0.1:9000")

	_, err := client.RunAnalyzerThenGetReport("MaxMind_GeoIP_3_0", a, "30seconds")
	if err != nil {
		t.Error("Can't run analyzer and get report")
	}
}

func TestAnalyzeData(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping AnalyzeData")
	}

	client := NewClient("http://127.0.0.1:9000")

	messages, err := client.AnalyzeData(a, "1minute")
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
