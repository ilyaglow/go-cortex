package gocortex

import (
	"encoding/json"
	"fmt"
	"sync"
)

const analyzersURL = "/api/analyzer"

// Analyzer defines a specific Cortex Analyzer
// https://github.com/CERT-BDF/CortexDocs/blob/master/api/get-analyzer.md
type Analyzer struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Version      string   `json:"version"`
	DataTypeList []string `json:"dataTypeList"`
}

// ListAnalyzers retrieves all analyzers that are available.
// Analyzers can be filtered by a datatype parameter. When "*" is used as a parameter, function returns all analyzers.
func (c *Client) ListAnalyzers(datatype string) ([]Analyzer, error) {
	requestURL := analyzersURL

	if datatype != "*" {
		requestURL = analyzersURL + "/type/" + datatype
	}

	r, _, err := c.sendRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	a := []Analyzer{}
	if err := json.Unmarshal(r, &a); err != nil {
		return nil, err
	}

	return a, nil
}

// GetAnalyzer retrieves an Analyzer by its' ID
func (c *Client) GetAnalyzer(id string) (*Analyzer, error) {
	r, s, err := c.sendRequest("GET", analyzersURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, fmt.Errorf("Can't find the analyzer with an id %s", id)
	}

	a := &Analyzer{}
	if err := json.Unmarshal(r, a); err != nil {
		return nil, err
	}

	return a, nil
}

// RunAnalyzer runs a selected analyzer for a specified job
func (c *Client) RunAnalyzer(id string, data *Artifact) (*Job, error) {
	jsonData, _ := json.Marshal(data)

	r, _, err := c.sendRequest("POST", analyzersURL+"/"+id+"/run", &jsonData)
	if err != nil {
		return nil, err
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, err
	}

	return j, nil
}

// RunAnalyzerThenGetReport is a helper function that combines multiple functions to return JobReport providing more clear API
func (c *Client) RunAnalyzerThenGetReport(id string, data *Artifact, timeout string) (*JobReport, error) {
	j, err := c.RunAnalyzer(id, data)
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
func (c *Client) AnalyzeData(data *Artifact, timeout string) (<-chan *JobReport, error) {
	var wg sync.WaitGroup
	reports := make(chan *JobReport)

	analyzers, err := c.ListAnalyzers(data.Attributes.DataType)
	if err != nil {
		return nil, err
	}

	wg.Add(len(analyzers))
	for _, a := range analyzers {
		go func(an Analyzer) {
			defer wg.Done()

			report, err := c.RunAnalyzerThenGetReport(an.ID, data, timeout)
			if err == nil {
				reports <- report
			} else {
				c.log(fmt.Sprintf("Failed to process %s with %s", data.Data, an.Name))
			}
		}(a)
	}

	go func() {
		wg.Wait()
		close(reports)
	}()

	return reports, nil
}
