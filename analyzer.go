package cortex

import (
	"context"
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
	Author        string                 `json:"author"`
	BaseConfig    string                 `json:"baseConfig"`
	Configuration map[string]interface{} `json:"configuration"`
	CreatedAt     int64                  `json:"createdAt"`
	CreatedBy     string                 `json:"createdBy"`
	DataTypeList  []string               `json:"dataTypeList"`
	DefinitionID  string                 `json:"analyzerDefinitionId"`
	Description   string                 `json:"description"`
	ID            string                 `json:"id"`
	JobCache      interface{}            `json:"jobCache,omitempty"` // unknown
	License       string                 `json:"license"`
	Name          string                 `json:"name"`
	Rate          int                    `json:"rate,omitempty"`
	RateUnit      string                 `json:"rateUnit,omitempty"`
	URL           string                 `json:"url"`
	UpdatedAt     int64                  `json:"updatedAt,omitempty"`
	UpdatedBy     string                 `json:"updatedBy,omitempty"`
	Version       string                 `json:"version"`
}

// AnalyzerService is an interface for managing analyzers
type AnalyzerService interface {
	Get(context.Context, string) (*Analyzer, *http.Response, error)
	List(context.Context) ([]Analyzer, *http.Response, error)
	ListByType(context.Context, string) ([]Analyzer, *http.Response, error)
	Run(context.Context, string, Observable, time.Duration) (*Report, error)
	StartJob(context.Context, string, Observable) (*Job, *http.Response, error)
	NewMultiRun(context.Context, time.Duration) *MultiRun
	DataTypes(context.Context) ([]string, error)
}

// AnalyzerServiceOp handles analyzer methods from Cortex API
type AnalyzerServiceOp struct {
	client *Client
}

// Get a specified Cortex analyzer by its name
func (a *AnalyzerServiceOp) Get(ctx context.Context, id string) (*Analyzer, *http.Response, error) {
	als, resp, err := a.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	var alid string
	for i := range als {
		if als[i].Name == id {
			alid = als[i].ID
			break
		}
	}

	if alid == "" {
		return nil, resp, fmt.Errorf("no analyzer found with name %s", id)
	}

	req, err := a.client.NewRequest("GET", fmt.Sprintf(analyzersURL+"/%s", alid), nil)
	if err != nil {
		return nil, nil, err
	}

	var an Analyzer
	resp, err = a.client.Do(ctx, req, &an)
	if err != nil {
		return nil, resp, err
	}

	return &an, resp, err
}

// List all Cortex analyzers with pagination
func (a *AnalyzerServiceOp) List(ctx context.Context) ([]Analyzer, *http.Response, error) {
	var analyzers []Analyzer

	start := 0

	for {
		pagedURL := fmt.Sprintf("%s?range=%d-%d", analyzersURL, start, a.client.PageSize)
		req, err := a.client.NewRequest("GET", pagedURL, nil)
		if err != nil {
			return nil, nil, err
		}

		var paginatedAns []Analyzer
		resp, err := a.client.Do(ctx, req, &paginatedAns)
		if err != nil {
			return nil, resp, err
		}

		if len(paginatedAns) < a.client.PageSize {
			analyzers = append(analyzers, paginatedAns...)
			break
		}

		analyzers = append(analyzers, paginatedAns...)
		start = start + a.client.PageSize
	}

	return analyzers, nil, nil
}

// ListByType lists Cortex analyzers by datatype
func (a *AnalyzerServiceOp) ListByType(ctx context.Context, t string) ([]Analyzer, *http.Response, error) {
	req, err := a.client.NewRequest("GET", analyzersByType+t, nil)
	if err != nil {
		return nil, nil, err
	}

	var analyzers []Analyzer
	resp, err := a.client.Do(ctx, req, &analyzers)
	if err != nil {
		return nil, resp, err
	}

	return analyzers, resp, nil
}

// Run will start the observable analysis using specified analyzer,
// wait for a certain duration and return a report
func (a *AnalyzerServiceOp) Run(ctx context.Context, anid string, o Observable, d time.Duration) (*Report, error) {
	an, _, err := a.Get(ctx, anid)
	if err != nil {
		return nil, err
	}

	return a.run(ctx, an.ID, o, d)
}

// run is a more lighter version that uses Cortex Analyzer ID directly
func (a *AnalyzerServiceOp) run(ctx context.Context, id string, o Observable, d time.Duration) (*Report, error) {
	j, _, err := a.StartJob(ctx, id, o)
	if err != nil {
		return nil, err
	}

	jso := &JobServiceOp{a.client}
	report, resp, err := jso.WaitReport(ctx, j.ID, d)
	if err != nil {
		if resp != nil && resp.StatusCode == 500 {
			return nil, fmt.Errorf("job passed maximum execution time %s", d.String())
		}

		if resp != nil && resp.StatusCode == 429 {
			return nil, errors.New("rate limit exceeded")
		}

		return nil, err
	}

	return report, err
}

// StartJob starts observable analysis
func (a *AnalyzerServiceOp) StartJob(ctx context.Context, anid string, o Observable) (*Job, *http.Response, error) {
	var req *http.Request
	var err error

	switch o.Type() {
	case "file":
		obsData := o.(*FileTask)
		req, err = a.client.NewFileRequest("POST", fmt.Sprintf(analyzersURL+"/%s/run", anid), &obsData, obsData.FileName, obsData.Reader)
		if err != nil {
			return nil, nil, err
		}

	default:
		obsData := o.(*Task)
		req, err = a.client.NewRequest("POST", fmt.Sprintf(analyzersURL+"/%s/run", anid), &obsData)
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

// DataTypes returns all available data types that Cortex can analyse.
// The entries are not sorted.
func (a *AnalyzerServiceOp) DataTypes(ctx context.Context) ([]string, error) {
	ans, _, err := a.List(ctx)
	if err != nil {
		return nil, err
	}

	dtm := make(map[string]bool)
	for _, a := range ans {
		addDataTypes(dtm, a.DataTypeList)
	}

	var dts []string
	for k := range dtm {
		dts = append(dts, k)
	}

	return dts, nil
}

func addDataTypes(m map[string]bool, dts []string) {
	for _, dt := range dts {
		if _, ok := m[dt]; !ok {
			m[dt] = true
		}
	}
}
