package gocortex

import (
	"encoding/json"
	"testing"
)

var listJobsResponse []byte = []byte(`
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

var analysisJobResponse []byte = []byte(`
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

var getJobReportResponse []byte = []byte(`
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
        "type": "sha1",
        "value": "cd1c2da4de388a4b5b60601f8b339518fe8fbd31"
      },
      {
        "type": "sha256",
        "value": "fd1755c7f1f0f85597cf2a1f13f5cbe0782d9e5597aca410da0d5f26cda26b97"
      },
      {
        "type": "md5",
        "value": "3aa598d1f0d50228d48fe3a792071dde"
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

func TestListJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListJobs")
	}

	client := NewClient("http://127.0.0.1:9000")

	_, err := client.ListJobs()
	if err != nil {
		t.Error("Can't list jobs")
	}
}

func TestListFilteredJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ListFilteredJobs")
	}

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
			if af.AType != "sha1" {
				t.Error("Wrong artifact type")
			}

			if af.Value != "cd1c2da4de388a4b5b60601f8b339518fe8fbd31" {
				t.Error("Wrong artifact value")
			}
		}
	}
}
