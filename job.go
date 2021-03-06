package cortex

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	jobsURL = APIRoute + "/job"
)

// Task represents a Cortex task to run
type Task struct {
	Data       string      `json:"data,omitempty"`
	DataType   string      `json:"dataType,omitempty"`
	TLP        *TLP        `json:"tlp,omitempty"`
	PAP        *PAP        `json:"pap,omitempty"`
	Message    string      `json:"message,omitempty"`
	Parameters interface{} `json:"parameters,omitempty"`
}

// Type returns DataType of the task, satisfying an Observable interface
func (t *Task) Type() string {
	return t.DataType
}

// Description returns Data of the task, satisfying an Observable interface
func (t *Task) Description() string {
	return t.Data
}

// FileTask is a file to be analyzed
type FileTask struct {
	FileTaskMeta
	Reader   io.Reader
	FileName string
}

// FileTaskMeta represents meta data of the file observable
type FileTaskMeta struct {
	DataType string `json:"dataType"`
	TLP      *TLP   `json:"tlp,omitempty"`
	PAP      *PAP   `json:"pap,omitempty"`
}

// Type usually returns just a string "file" for a file task
func (f *FileTask) Type() string {
	return f.FileTaskMeta.DataType
}

// Description returns a file name
func (f *FileTask) Description() string {
	return f.FileName
}

// Job is a sample Cortex job
type Job struct {
	Task
	ID                   string `json:"id"`
	AnalyzerDefinitionID string `json:"analyzerDefinitionId"`
	AnalyzerID           string `json:"analyzerID"`
	AnalyzerName         string `json:"analyzerName"`
	Status               string `json:"status"`
	Organization         string `json:"organization"`
	StartDate            int64  `json:"startDate"`
	EndDate              int64  `json:"endDate"`
	Date                 int64  `json:"date"`
	CreatedAt            int64  `json:"createdAt"`
	CreatedBy            string `json:"createdBy"`
	UpdatedAt            int64  `json:"updatedAt,omitempty"`
	UpdatedBy            string `json:"updatedBy,omitempty"`
}

// Taxonomy represents a taxonomy object in a report
type Taxonomy struct {
	Predicate string      `json:"predicate"`
	Namespace string      `json:"namespace"`
	Value     interface{} `json:"value"`
	Level     string      `json:"level"`
}

// Report represents a struct returned by the Cortex
type Report struct {
	Job
	ReportBody ReportBody `json:"report,omitempty"`
}

// Taxonomies is a shortcut to get taxonomies from the report
func (r *Report) Taxonomies() []Taxonomy {
	return r.ReportBody.Summary.Taxonomies
}

// Artifact represents an artifact
type Artifact struct {
	DataType  string `json:"dataType"`
	CreatedBy string `json:"createdBy"`
	CreatedAt int64  `json:"createdAt"`
	Data      string `json:"data"`
	TLP       TLP    `json:"tlp"`
	PAP       PAP    `json:"pap"`
	ID        string `json:"id"`
}

// Summary is a customized report object which may have taxonomies
type Summary struct {
	Taxonomies []Taxonomy `json:"taxonomies,omitempty"`
}

// ReportBody represents a report with analyzer results
type ReportBody struct {
	Artifacts    []Artifact  `json:"artifacts,omitempty"`
	FullReport   interface{} `json:"full,omitempty"`
	Success      bool        `json:"success,omitempty"`
	Summary      Summary     `json:"summary,omitempty"`
	ErrorMessage string      `json:"errorMessage,omitempty"`
	Input        string      `json:"input,omitempty"`
}

// Observable is an interface for string type artifact and file type artifact
type Observable interface {
	Type() string
	Description() string
}

// JobService is an interface for managing jobs
type JobService interface {
	Get(context.Context, string) (*Job, *http.Response, error)
	GetReport(context.Context, string) (*Report, *http.Response, error)
	WaitReport(context.Context, string, time.Duration) (*Report, *http.Response, error)
	Delete(context.Context, string) (*http.Response, error)
}

// JobServiceOp handles cases methods from the Cortex API
type JobServiceOp struct {
	client *Client
}

// Get retrieves a Job by it's ID
func (j *JobServiceOp) Get(ctx context.Context, jobid string) (*Job, *http.Response, error) {
	req, err := j.client.NewRequest("GET", fmt.Sprintf(jobsURL+"/%s", jobid), nil)
	if err != nil {
		return nil, nil, err
	}

	var job Job
	resp, err := j.client.Do(ctx, req, &job)
	if err != nil {
		return nil, nil, err
	}

	return &job, resp, nil
}

// GetReport retrieves the analysis Report by a job ID
func (j *JobServiceOp) GetReport(ctx context.Context, jobid string) (*Report, *http.Response, error) {
	req, err := j.client.NewRequest("GET", fmt.Sprintf(jobsURL+"/%s/report", jobid), nil)
	if err != nil {
		return nil, nil, err
	}

	var r Report
	resp, err := j.client.Do(ctx, req, &r)
	if err != nil {
		return nil, nil, err
	}

	return &r, resp, nil
}

// WaitReport synchronously waits a certain job id for a specified duration of time
// and returns a report
func (j *JobServiceOp) WaitReport(ctx context.Context, jid string, d time.Duration) (*Report, *http.Response, error) {
	sd := strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + "seconds"
	req, err := j.client.NewRequest("GET", fmt.Sprintf(jobsURL+"/%s/waitreport?atMost=%s", jid, sd), nil)
	if err != nil {
		return nil, nil, err
	}

	var report Report
	resp, err := j.client.Do(ctx, req, &report)
	if err != nil {
		if resp != nil {
			return nil, resp, err
		}
		return nil, nil, err
	}

	return &report, resp, err
}

// Delete the job from Cortex. This marks the job as Deleted. However the job's
// data is not removed from the database.
func (j *JobServiceOp) Delete(ctx context.Context, jobid string) (*http.Response, error) {
	req, err := j.client.NewRequest("DELETE", fmt.Sprintf(jobsURL+"/%s", jobid), nil)
	if err != nil {
		return nil, err
	}

	resp, err := j.client.Do(ctx, req, nil)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
