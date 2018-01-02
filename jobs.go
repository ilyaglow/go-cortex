package cortex

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-querystring/query"
)

const jobsURL = "/api/job"

// ArtifactAttributes struct represents Artifact Attributes
type ArtifactAttributes struct {
	DataType    string `json:"dataType"`
	TLP         int    `json:"tlp,omitempty"`
	ContentType string `json:"content-type,omitempty"`
	Filename    string `json:"filename,omitempty"`
}

// JobBody is deprecated and is left for the compatilibity
type JobBody Artifact

// Artifact represents an artifact which can be supplied for the analysis
// and retrieved from a job later
type Artifact struct {
	Attributes ArtifactAttributes `json:"attributes"`
	Data       string             `json:"data,omitempty"`
}

// Job defines an analysis job
type Job struct {
	ID         string  `json:"id"`
	AnalyzerID string  `json:"analyzerId"`
	Status     string  `json:"status"`
	Date       int64   `json:"date"`
	Artifact   JobBody `json:"artifact"`
}

// JobReport represents a job response.
//
// More info: https://github.com/CERT-BDF/CortexDocs/blob/master/api/get-job-report.md
type JobReport struct {
	Job
	Report ReportBody `json:"report"`
}

// summary is a customized report object which may have taxonomies
type summary struct {
	Taxonomies []Taxonomy `json:"taxonomies,omitempty"`
}

// ReportBody defines a report for a given job.
// FullReport and Summary are arbitrary objects.
type ReportBody struct {
	Artifacts  []JobBody   `json:"artifacts"`
	FullReport interface{} `json:"full"`
	Success    bool        `json:"success"`
	Summary    summary     `json:"summary"`
}

// JobsFilter is used to filter ListJobs results
type JobsFilter struct {
	Analyzer string `url:"analyzerFilter,omitempty"`
	DataType string `url:"dataTypeFilter,omitempty"`
	Data     string `url:"dataFilter,omitempty"`
	start    int    `url:"start,omitempty"`
	limit    int    `url:"limit,omitempty"`
}

// Taxonomy represents a taxonomy object in a report
type Taxonomy struct {
	Predicate string `json:"predicate"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
	Level     string `json:"level"`
}

// Taxonomies retrieves all taxonomies from a JobReport
func (j *JobReport) Taxonomies() []Taxonomy {
	return j.Report.Summary.Taxonomies
}

// ListJobs shows all available jobs
func (c *Client) ListJobs() ([]Job, error) {
	r, _, err := c.sendRequest("GET", jobsURL, nil)
	if err != nil {
		return nil, err
	}

	if string(r) == "[]" {
		return nil, nil
	}

	j := []Job{}
	if err := json.Unmarshal(r, &j); err != nil {
		return nil, err
	}

	return j, nil
}

// ListFilteredJobs shows available filtered jobs
func (c *Client) ListFilteredJobs(f *JobsFilter) ([]Job, error) {
	v, _ := query.Values(f)

	r, _, err := c.sendRequest("GET", jobsURL+"?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if string(r) == "[]" {
		return nil, nil
	}

	j := []Job{}
	if err := json.Unmarshal(r, &j); err != nil {
		return nil, err
	}

	return j, nil
}

// GetJob retrieves a Job by its ID
func (c *Client) GetJob(id string) (*Job, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, fmt.Errorf("Job ID %s is not found", id)
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, err
	}

	return j, nil
}

// WaitForJob do synchronously wait for a report
// Duration should be in a string format, for example:
//	1minute
//	30seconds
//
// If the duration is too small a report with a null value will be returned
func (c *Client) WaitForJob(id string, duration string) (*Job, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id+"/waitreport?atMost="+duration, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, fmt.Errorf("Job ID %s is not found", id)
	}

	if s == 500 {
		return nil, fmt.Errorf("Wait report request failed: %s", string(r))
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, err
	}

	return j, nil

}

// GetJobReport retrieves a JobReport by Job ID
func (c *Client) GetJobReport(id string) (*JobReport, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id+"/report", nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, fmt.Errorf("Job ID %s is not found", id)
	}

	j := &JobReport{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, err
	}

	return j, nil
}

// DeleteJob deletes an existing job identified by its ID
func (c *Client) DeleteJob(id string) (bool, error) {
	_, s, err := c.sendRequest("DELETE", jobsURL+"/"+id, nil)
	if err != nil {
		return false, err
	}

	switch s {
	case 200:
		return true, nil
	case 404:
		return false, fmt.Errorf("Job ID %s is not found", id)
	case 500:
		return false, errors.New("Internal server error")
	}

	return false, nil
}
