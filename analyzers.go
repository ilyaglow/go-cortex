package cortex

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

const (
	analyzersURL    = "/api/analyzer"
	analyzersByType = analyzersURL + "/type/"
)

// Analyzer defines a specific Cortex Analyzer
//
// More info: https://github.com/CERT-BDF/CortexDocs/blob/master/api/get-analyzer.md
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

// ListAnalyzers retrieves all analyzers that are available.
// Analyzers can be filtered by a datatype parameter.
// When "*" is used as a parameter, function returns all analyzers.
func (c *Client) ListAnalyzers(datatype string) ([]Analyzer, error) {
	requestURL := analyzersURL

	if datatype != "*" {
		requestURL = analyzersURL + "/type/" + datatype
	}

	r, err := c.sendRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	var a []Analyzer
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		return nil, err
	}
	r.Body.Close()

	return a, nil
}

// GetAnalyzer retrieves an Analyzer by its' ID
func (c *Client) GetAnalyzer(id string) (*Analyzer, error) {
	r, err := c.sendRequest("GET", analyzersURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	if r.StatusCode == 404 {
		return nil, fmt.Errorf("Can't find the analyzer with an id %s", id)
	}

	a := &Analyzer{}
	if err := json.NewDecoder(r.Body).Decode(a); err != nil {
		return nil, err
	}
	r.Body.Close()

	return a, nil
}

// RunAnalyzer runs a selected analyzer for a specified job
func (c *Client) RunAnalyzer(id string, obs Observable) (*Job, error) {
	var resp *http.Response
	var err error

	switch obs.Type() {
	case "file":
		far := obs.(*FileArtifact)
		obsData, err := json.Marshal(far.FileArtifactMeta)
		if err != nil {
			return nil, err
		}
		resp, err = c.sendFileRequest(obsData, analyzersURL+"/"+id+"/run", far.FileName, far.Reader)
		if err != nil {
			return nil, err
		}
	default:
		obsData, err := json.Marshal(obs.(*Artifact))
		if err != nil {
			return nil, err
		}
		resp, err = c.sendRequest("POST", analyzersURL+"/"+id+"/run", &obsData)
		if err != nil {
			return nil, err
		}

	}
	j := &Job{}
	if err = json.NewDecoder(resp.Body).Decode(j); err != nil {
		return nil, err
	}
	// resp.Body.Close()

	return j, nil
}

// RunAnalyzerThenGetReport is a helper function that combines multiple
// functions to return JobReport providing more clear API
func (c *Client) RunAnalyzerThenGetReport(id string, obs Observable, timeout string) (*JobReport, error) {
	j, err := c.RunAnalyzer(id, obs)
	if err != nil {
		c.log(fmt.Sprintf("Failed to run the analyzer %s", id))
		return nil, err
	}

	w, err := c.WaitForJob(j.ID, timeout)
	if err != nil {
		c.log(fmt.Sprintf("Failed to wait for the job %s", j.ID))
		return nil, err
	}

	r, err := c.GetJobReport(w.ID)
	if err != nil {
		c.log(fmt.Sprintf("Failed to get the job report %s", w.ID))
		return nil, err
	}

	return r, nil
}

// AnalyzeData runs all analyzers suitable for a specified job and returns a channel with reports
func (c *Client) AnalyzeData(obs Observable, timeout string) (<-chan *JobReport, error) {
	var wg sync.WaitGroup
	reports := make(chan *JobReport)

	analyzers, err := c.ListAnalyzers(obs.Type())
	if err != nil {
		return nil, err
	}
	log.Println(analyzers)

	wg.Add(len(analyzers))

	switch obs.(type) {
	case *FileArtifact:
		reports, err = c.analyzeFile(analyzers, obs.(*FileArtifact), &wg, timeout, reports)
		if err != nil {
			return nil, err
		}
	case *Artifact:
		reports, err = c.analyzeString(analyzers, obs, &wg, timeout, reports)
		if err != nil {
			return nil, err
		}
	}

	go func() {
		wg.Wait()
		close(reports)
	}()

	return reports, nil
}

func (c *Client) analyzeFile(analyzers []Analyzer, fa *FileArtifact, wg *sync.WaitGroup, timeout string, rch chan *JobReport) (chan *JobReport, error) {
	var readPipes []*io.PipeReader
	var writePipes []*io.PipeWriter

	for _, a := range analyzers {
		fr, fw := io.Pipe()
		readPipes = append(readPipes, fr)
		writePipes = append(writePipes, fw)

		o := &FileArtifact{
			FileName:         fa.FileName,
			Reader:           fr,
			FileArtifactMeta: fa.FileArtifactMeta,
		}

		go func(an Analyzer, f io.Reader) {
			defer wg.Done()
			c.log(fmt.Sprintf("Starting %s analyzer", an.Name))

			report, err := c.RunAnalyzerThenGetReport(an.ID, o, timeout)
			if err == nil && report != nil {
				rch <- report
			} else {
				c.log(fmt.Sprintf("Failed to process %s with %s", o.Description(), an.Name))
			}
		}(a, fr)
	}

	wr := make([]io.Writer, len(writePipes))
	for i := range writePipes {
		wr[i] = writePipes[i]
	}

	mw := io.MultiWriter(wr...)
	go func() {
		if _, err := io.Copy(mw, fa.Reader); err != nil {
			log.Fatal(err)
		}
		for i := range writePipes {
			writePipes[i].Close()
		}
	}()

	return rch, nil
}

func (c *Client) analyzeString(analyzers []Analyzer, obs Observable, wg *sync.WaitGroup, timeout string, rch chan *JobReport) (chan *JobReport, error) {
	for _, a := range analyzers {
		go func(an Analyzer) {
			defer wg.Done()

			report, err := c.RunAnalyzerThenGetReport(an.ID, obs, timeout)
			if err == nil {
				rch <- report
			} else {
				c.log(fmt.Sprintf("Failed to process %s with %s", obs.Description(), an.Name))
			}
		}(a)
	}

	return rch, nil
}
