package cortex

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
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
	RunAll(context.Context, Observable, time.Duration) (<-chan *Report, error)
	StartJob(context.Context, string, Observable) (*Job, *http.Response, error)
}

// AnalyzerServiceOp handles analyzer methods from Cortex API
type AnalyzerServiceOp struct {
	client *Client
}

// Get a specified Cortex analyzer
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

	j, _, err := a.StartJob(ctx, an.ID, o)
	if err != nil {
		return nil, err
	}

	jso := &JobServiceOp{a.client}
	_, resp, err := jso.WaitForAJob(ctx, j.ID, d)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error waiting for a job report %s", resp.Status)
	}

	r, _, err := jso.GetReport(ctx, j.ID)
	if err != nil {
		return nil, err
	}

	return r, err
}

// RunAll will start the observable analysis using specified analyzer,
// wait for a certain duration and return a report
func (a *AnalyzerServiceOp) RunAll(ctx context.Context, o Observable, d time.Duration) (<-chan *Report, error) {
	ans, _, err := a.ListByType(ctx, o.Type())
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(len(ans))

	var reports chan *Report

	switch o.(type) {
	case *FileTask:
		reports = a.AnalyzeFile(ctx, o.(*FileTask), &wg, d, ans...)
	case *Task:
		reports = a.AnalyzeString(ctx, o.(*Task), &wg, d, ans...)
	}

	go func() {
		wg.Wait()
		close(reports)
	}()

	return reports, nil
}

// AnalyzeFile analyses a file observable by multiple analyzers
func (a *AnalyzerServiceOp) AnalyzeFile(ctx context.Context, ft *FileTask, wg *sync.WaitGroup, td time.Duration, ans ...Analyzer) chan *Report {
	var (
		readPipes  []*io.PipeReader
		writePipes []*io.PipeWriter
	)
	rch := make(chan *Report, 100)

	for i := range ans {
		fr, fw := io.Pipe()
		readPipes = append(readPipes, fr)
		writePipes = append(writePipes, fw)

		o := &FileTask{
			FileName:     ft.FileName,
			Reader:       fr,
			FileTaskMeta: ft.FileTaskMeta,
		}

		go func(an Analyzer, f io.Reader) {
			defer wg.Done()

			report, err := a.Run(ctx, an.ID, o, td)
			if err == nil && report != nil {
				rch <- report
			}

		}(ans[i], fr)
	}

	wr := make([]io.Writer, len(writePipes))
	for i := range writePipes {
		wr[i] = writePipes[i]
	}

	mw := io.MultiWriter(wr...)
	go func() {
		if _, err := io.Copy(mw, ft.Reader); err != nil {
			log.Println(err)
		}
		for i := range writePipes {
			writePipes[i].Close()
		}
	}()

	return rch
}

// AnalyzeString analyses a basic string-alike observable by multiple analyzers
func (a *AnalyzerServiceOp) AnalyzeString(ctx context.Context, t *Task, wg *sync.WaitGroup, td time.Duration, ans ...Analyzer) chan *Report {
	rch := make(chan *Report, 100)
	for i := range ans {
		go func(an Analyzer) {
			defer wg.Done()

			report, err := a.Run(ctx, an.ID, t, td)
			if err == nil && report != nil {
				rch <- report
			}
		}(ans[i])
	}

	return rch
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
