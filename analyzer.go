package cortex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	analyzersURL    = APIRoute + "/analyzer"
	analyzersByType = analyzersURL + "/type/"
)

// Analyzer defines a specific Cortex Analyzer
type Analyzer struct {
	Author       string      `json:"author"`
	BaseConfig   string      `json:"baseConfig"`
	CreatedAt    int64       `json:"createdAt"`
	CreatedBy    string      `json:"createdBy"`
	DataTypeList []string    `json:"dataTypeList"`
	DefinitionID string      `json:"analyzerDefinitionId"`
	Description  string      `json:"description"`
	ID           string      `json:"id"`
	JobCache     interface{} `json:"jobCache,omitempty"` // unknown
	License      string      `json:"license"`
	Name         string      `json:"name"`
	Rate         int         `json:"rate,omitempty"`
	RateUnit     string      `json:"rateUnit,omitempty"`
	URL          string      `json:"url"`
	UpdatedAt    int64       `json:"updatedAt,omitempty"`
	UpdatedBy    string      `json:"updatedBy,omitempty"`
	Version      string      `json:"version"`
}

// AnalyzerService is an interface for managing analyzers
type AnalyzerService interface {
	Get(context.Context, string) (*Analyzer, *http.Response, error)
	List(context.Context) ([]Analyzer, *http.Response, error)
	Run(context.Context, string, Observable, time.Duration) (*Report, error)
}

// AnalyzerServiceOp handles analyzer methods from Cortex API
type AnalyzerServiceOp struct {
	client *Client
}

// Get a specified Cortex analyzer
func (a *AnalyzerServiceOp) Get(ctx context.Context, id string) (*Analyzer, *http.Response, error) {
	req, err := a.client.NewRequest("GET", fmt.Sprintf(analyzersURL+"/%s", id), nil)
	if err != nil {
		return nil, nil, err
	}

	var an Analyzer
	resp, err := a.client.Do(ctx, req, &an)
	if err != nil {
		return nil, resp, err
	}

	return &an, resp, err
}

// List all Cortex analyzers
func (a *AnalyzerServiceOp) List(ctx context.Context) ([]Analyzer, *http.Response, error) {
	var analyzers []Analyzer

	req, err := a.client.NewRequest("GET", analyzersURL, nil)
	if err != nil {
		return nil, nil, err
	}

	resp, err := a.client.Do(ctx, req, &analyzers)
	if err != nil {
		return nil, resp, err
	}

	return analyzers, resp, nil
}

// Run will start the observable analysis using specified analyzer,
// wait for a certain duration and return a report
func (a *AnalyzerServiceOp) Run(ctx context.Context, anid string, o Observable, d time.Duration) (*Report, error) {
	j, _, err := a.StartJob(ctx, anid, o)
	if err != nil {
		return nil, err
	}

	_, _, err = a.WaitForAJob(ctx, j.ID, d)
	if err != nil {
		return nil, err
	}

	jso := &JobServiceOp{client: a.client}
	r, _, err := jso.GetReport(ctx, j.ID)
	if err != nil {
		return nil, err
	}

	return r, err
}

// StartJob starts observable analysis
func (a *AnalyzerServiceOp) StartJob(ctx context.Context, anid string, o Observable) (*Job, *http.Response, error) {
	var req *http.Request

	switch o.Type() {
	case "file":
		return nil, nil, errors.New("not implemented yet")
	default:
		obsData, err := json.Marshal(o.(*Task))
		if err != nil {
			return nil, nil, err
		}

		req, err = a.client.NewRequest("POST", fmt.Sprintf(analyzersURL+"/anid/%s/run", anid), &obsData)
		if err != nil {
			return nil, nil, err
		}

	}

	var j Job
	resp, err := a.client.Do(ctx, req, &j)
	if err != nil {
		return nil, nil, err
	}

	return &j, resp, nil
}

// WaitForAJob synchronously waits a certain job id for a specified duration of time
// and returns a report
func (a *AnalyzerServiceOp) WaitForAJob(ctx context.Context, jid string, d time.Duration) (*Job, *http.Response, error) {
	sd := d.String()
	req, err := a.client.NewRequest("GET", fmt.Sprintf(jobsURL+"/%s/waitreport?atMost=%s", jid, sd), nil)
	if err != nil {
		return nil, nil, err
	}

	var j Job
	resp, err := a.client.Do(ctx, req, &j)
	if err != nil {
		return nil, nil, err
	}

	return &j, resp, err
}
