package gocortex

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/google/go-querystring/query"
)

const jobsURL = "/api/job"

//ArtifactAttributes represent particular attributes
type ArtifactAttributes struct {
	DataType    string `json:"dataType"`
	TLP         int    `json:"tlp"`
	ContentType string `json:"content-type,omitempty"`
	Filename    string `json:"filename,omitempty"`
}

//JobBody represents artifact retrieved from a job
//and the data supplied for the analyzer to run
type JobBody struct {
	Attributes ArtifactAttributes `json:"attributes"`
	Data       string             `json:"data,omitempty"`
}

//Job defines a typical analyzer job
type Job struct {
	ID         string  `json:"id"`
	AnalyzerID string  `json:"analyzerId"`
	Status     string  `json:"status"`
	Date       int64   `json:"date"`
	Artifact   JobBody `json:"artifact"`
}

//JobReport represents a job response
//More info: https://github.com/CERT-BDF/CortexDocs/blob/master/api/get-job-report.md
type JobReport struct {
	Job
	Report ReportBody `json:"report"`
}

type reportArtifact struct {
	AType string `json:"type"`
	Value string `json:"value"`
}

type summary struct {
	Taxonomies []Taxonomy `json:"taxonomies,omitempty"`
}

//ReportBody defines report of a given job
//FullReport and Summary are arbitrary objects
type ReportBody struct {
	Artifacts  []reportArtifact `json:"artifacts"`
	FullReport interface{}      `json:"full"`
	Success    bool             `json:"success"`
	Summary    summary          `json:"summary"`
}

//JobsFilter used to filter ListJobs results
type JobsFilter struct {
	Analyzer string `url:"analyzerFilter,omitempty"`
	DataType string `url:"dataTypeFilter,omitempty"`
	Data     string `url:"dataFilter,omitempty"`
	start    int    `url:"start,omitempty"`
	limit    int    `url:"limit,omitempty"`
}

//Taxonomy represents taxonomy object in the report
type Taxonomy struct {
	Predicate string `json:"predicate"`
	Namespace string `json:"namespace"`
	Value     string `json:"value"`
	Level     string `json:"level"`
}

//Taxonomies retrieves all taxonomies from JobReport
func (j *JobReport) Taxonomies() []Taxonomy {
	return j.Report.Summary.Taxonomies
}

//ListJobs shows all available jobs
//Returns slice of Jobs
func (c *Client) ListJobs() ([]Job, error) {
	r, _, err := c.sendRequest("GET", jobsURL, nil)
	if err != nil {
		return nil, err
	}

	if string(r) == "[]" {
		log.Println("No jobs available")
		return nil, nil
	}

	j := []Job{}
	if err := json.Unmarshal(r, &j); err != nil {
		return nil, errors.New("Can't unmarshal Jobs list")
	}

	return j, nil
}

//ListFilteredJobs shows available filtered jobs
//Returns slice of Jobs
func (c *Client) ListFilteredJobs(f *JobsFilter) ([]Job, error) {
	v, _ := query.Values(f)

	r, _, err := c.sendRequest("GET", jobsURL+"?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if string(r) == "[]" {
		log.Println("No jobs available")
		return nil, nil
	}

	j := []Job{}
	if err := json.Unmarshal(r, &j); err != nil {
		return nil, errors.New("Can't unmarshal Jobs list")
	}

	return j, nil
}

//GetJob retrieves a Job by its ID
func (c *Client) GetJob(id string) (*Job, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, errors.New("Job ID not found")
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, errors.New("Can't unmarshal Job body")
	}

	return j, nil
}

//WaitForJob do synchronously wait for the Job result
func (c *Client) WaitForJob(id string, duration string) (*Job, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id+"/waitreport?atMost="+duration, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, errors.New("Job ID not found")
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, errors.New("Can't unmarshal Job body")
	}

	return j, nil

}

//GetJobReport retrieves a JobReport by Job ID
func (c *Client) GetJobReport(id string) (*JobReport, error) {
	r, s, err := c.sendRequest("GET", jobsURL+"/"+id+"/report", nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, errors.New("Job ID is not found")
	}

	j := &JobReport{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, errors.New("Can't unmarshal Job report body")
	}

	return j, nil
}

//DeleteJob deletes and existing job, identified by its ID
func (c *Client) DeleteJob(id string) (bool, error) {
	_, s, err := c.sendRequest("DELETE", c.Location+jobsURL+"/"+id, nil)
	if err != nil {
		return false, err
	}

	switch s {
	case 200:
		return true, nil
	case 404:
		return false, errors.New("Job not found")
	case 500:
		return false, errors.New("Internal server error")
	}

	return false, nil
}
