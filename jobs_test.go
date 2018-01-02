package cortex

import (
	"encoding/json"
	"strings"
	"testing"
)

var listJobsResponse = []byte(`
[
  {
    "id": "OsmbnQJGmeCgvDxP",
    "analyzerId": "OTXQuery_1_0",
    "status": "Failure",
    "date": 1490194495264,
    "artifact": {
      "data": "8.8.8.8",
      "attributes": {
        "dataType": "ip",
        "tlp": 2
      }
    }
  },
  {
    "id": "c9uZDbHBf32DdIVJ",
    "analyzerId": "MaxMind_GeoIP_2_0",
    "status": "Success",
    "date": 1490194495262,
    "artifact": {
      "data": "8.8.8.8",
      "attributes": {
        "dataType": "ip",
        "tlp": 2,
        "content-type": "text/x-python-script",
        "filename": "sample.py"
      }
    }
  },
  {
    "id": "OcFlZbLNNUsIiJZq",
    "analyzerId": "HippoMore_1_0",
    "status": "InProgress",
    "date": 1490194495259,
    "artifact": {
      "data": "8.8.8.8",
      "attributes": {
        "dataType": "ip",
        "tlp": 2
      }
    }
  }
]
`)

var analysisJobResponse = []byte(`
{
    "id": "ymlrxZB8efyZhFEg",
    "analyzerId": "Hipposcore_1_0",
    "status": "Success",
    "date": 1490263456480,
    "artifact": {
        "data": "mydomain.com",
        "attributes": {
            "dataType": "domain",
            "tlp": 2,
            "content-type": "text/x-python-script",
            "filename": "sample.py"
        }
    }
}
`)

var getJobReportResponse = []byte(`
{
  "id": "vVQu93ps4PwHOtLv",
  "analyzerId": "File_Info_1_0",
  "status": "Success",
  "date": 1490204071457,
  "artifact": {
    "attributes": {
      "dataType": "file",
      "tlp": 2,
      "content-type": "text/x-python-script",
      "filename": "sample.py"
    }
  },
  "report": {
    "artifacts": [
      {
        "data": "cd1c2da4de388a4b5b60601f8b339518fe8fbd31",
        "attributes": {
          "dataType": "sha1"
        }
      }
    ],
    "full": {
      "Mimetype": "text/x-python",
      "Identification": {
        "ssdeep": "24:8ca1hbLcd8yutXHbLcTtvbrbLcvtEbLcWmtlbLca66/5:8zHbLcdbOXbLc5jrbLcVEbLcPlbLcax",
        "SHA1": "cd1c2da4de388a4b5b60601f8b339518fe8fbd31",
        "SHA256": "fd1755c7f1f0f85597cf2a1f13f5cbe0782d9e5597aca410da0d5f26cda26b97",
        "MD5": "3aa598d1f0d50228d48fe3a792071dde"
      },
      "filetype": "python script",
      "Magic": "Python script, ASCII text executable",
      "Exif": {
        "ExifTool:ExifToolVersion": 10.36
      }
    },
    "success": true,
    "summary": {
      "taxonomies": [
        {
          "predicate": "Predicate",
          "namespace": "Namespace",
          "value": "\"Value\"",
          "level": "info"
        }
      ]
    }
  }
}
`)

var jf = &JobsFilter{
	Analyzer: "MaxMind_GeoIP_3_0",
	DataType: "ip",
}

func TestListJobsFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.ListJobs()
	if v != nil && nerr == nil {
		t.Error("ListJobs should have failed")
	}
}

func TestListJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListJobs with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")
	_, err := client.ListJobs()
	if err != nil {
		t.Error("Can't list jobs")
	}
}

func TestListFilteredJobsFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.ListFilteredJobs(jf)
	if v != nil && nerr == nil {
		t.Error("ListFilteredJobs should have failed")
	}
}

func TestListFilteredJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListFilteredJobs with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")

	_, err := client.ListFilteredJobs(jf)
	if err != nil {
		t.Errorf("Can't list filtered jobs: %s", err.Error())
	}

	var njf = &JobsFilter{
		Analyzer: "nonexistent",
		DataType: "nonexistent",
	}

	nr, nerr := client.ListFilteredJobs(njf)
	if nr != nil && nerr != nil {
		t.Errorf("ListFilteredJobs should have returned nils")
	}
}

func TestGetJobFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.GetJob("sample")
	if v != nil && nerr == nil {
		t.Error("GetJobReport should have failed")
	}
}

func TestGetJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping GetJobReport with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")
	res, err := client.GetJob("nonexistent")
	if res != nil && strings.Contains(err.Error(), "not found") != true {
		t.Error("GetJob should have failed")
	}
}

func TestGetJobReportFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.GetJobReport("sample")
	if v != nil && nerr == nil {
		t.Error("GetJobReport should have failed")
	}
}

func TestGetJobReport(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping GetJobReport with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")

	result, err := client.GetJobReport("nonexistent")
	if result != nil && strings.Contains(err.Error(), "not found") != true {
		t.Error("GetJobReport should have returned nil")
	}
}

func TestWaitForJobFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.WaitForJob("sample", "30seconds")
	if v != nil && nerr == nil {
		t.Error("WaitForJob should have failed")
	}
}

func TestWaitForJob(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping WaitForJob with a valid Cortex server")
	}

	client := NewClient("http://127.0.0.1:9000")

	// Check for a non-existent job
	r, err := client.WaitForJob("nonexistent", "1minute")
	if r != nil && strings.Contains(err.Error(), "not found") != true {
		t.Error("WaitForJob should have failed and return not found error")
	}

	// Wrong time duration format
	f, ferr := client.WaitForJob("notmatter", "wrong")
	if f != nil && ferr == nil {
		t.Error("WaitForJob should have failed, because the Cortex should have returned an http code 500")
	}

}

func TestDeleteJobFailing(t *testing.T) {
	nonvalidClient := NewClient("http://127.0.0.1:39900")

	v, nerr := nonvalidClient.DeleteJob("sample")
	if v != false && nerr == nil {
		t.Error("DeleteJob should have failed")
	}
}

func TestDeleteJob(t *testing.T) {
	client := NewClient("http://127.0.0.1:9000")

	result, err := client.DeleteJob("nonexistent")
	if result != false && strings.Contains(err.Error(), "not found") != true {
		t.Error("DeleteJob should have returned nil")
	}
}

func TestListJobsResponse(t *testing.T) {
	j := []Job{}
	if err := json.Unmarshal(listJobsResponse, &j); err != nil {
		t.Error("Can't unmarshal predefined list of jobs")
	}

	if len(j) != 3 {
		t.Error("Wrong number of predefined listed jobs")
	}
}

func TestJobBrief(t *testing.T) {
	j := Job{}
	if err := json.Unmarshal(analysisJobResponse, &j); err != nil {
		t.Error("Can't unmarshal predefined analysis job")
	}

	if j.ID != "ymlrxZB8efyZhFEg" {
		t.Error("Wrong ID")
	}

	if j.AnalyzerID != "Hipposcore_1_0" {
		t.Error("Wrong AnalyzerID")
	}

	if j.Status != "Success" {
		t.Error("Wrong status")
	}

	if j.Date != 1490263456480 {
		t.Error("Wrong date")
	}

	if j.Artifact.Data != "mydomain.com" {
		t.Error("Wrong artifact domain")
	}

	if j.Artifact.Attributes.DataType != "domain" {
		t.Error("Wrong attribute datatype")
	}

	if j.Artifact.Attributes.TLP != 2 {
		t.Error("Wrong attribute TLP")
	}

	if j.Artifact.Attributes.ContentType != "text/x-python-script" {
		t.Error("Wrong attribute content-type")
	}

	if j.Artifact.Attributes.Filename != "sample.py" {
		t.Error("Wrong attribute filename")
	}
}

func TestJobReport(t *testing.T) {
	j := JobReport{}

	if err := json.Unmarshal(getJobReportResponse, &j); err != nil {
		t.Error("Can't unmarshal predefined job report")
	}

	if j.Report.Success != true {
		t.Error("Wrong report success status")
	}

	for _, tx := range j.Taxonomies() {
		if tx.Predicate != "Predicate" {
			t.Error("Wrong taxonomy predicate")
		}

		if tx.Namespace != "Namespace" {
			t.Error("Wrong taxonomy namespace")
		}

		if tx.Value != `"Value"` {
			t.Error("Wrong taxonomy value")
		}

		if tx.Level != "info" {
			t.Error("Wrong taxonomy level")
		}
	}

	for i, af := range j.Report.Artifacts {
		switch i {
		case 0:
			if af.Attributes.DataType != "sha1" {
				t.Error("Wrong artifact data type")
			}

			if af.Data != "cd1c2da4de388a4b5b60601f8b339518fe8fbd31" {
				t.Error("Wrong artifact data value")
			}
		}
	}
}
