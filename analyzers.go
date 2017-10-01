package gocortex

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"sync"
)

const analyzersURL = "/api/analyzer"

//Analyzer defines data representing a specific analyzer
//https://github.com/CERT-BDF/CortexDocs/blob/master/api/get-analyzer.md
type Analyzer struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Version      string   `json:"version"`
	DataTypeList []string `json:"dataTypeList"`
}

//ListAnalyzers retrieves all analyzers available
//analyzers can be filtered by datatype parameter
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
		return nil, errors.New("Can't unmarshal Analyzers list")
	}

	return a, nil
}

//GetAnalyzer retrieves Analyzer by its' ID
func (c *Client) GetAnalyzer(id string) (*Analyzer, error) {
	r, s, err := c.sendRequest("GET", analyzersURL+"/"+id, nil)
	if err != nil {
		return nil, err
	}

	if s == 404 {
		return nil, errors.New("Can't find analyzer")
	}

	a := &Analyzer{}
	if err := json.Unmarshal(r, a); err != nil {
		return nil, errors.New("Can't unmarshal Analyzer body")
	}

	return a, nil
}

//RunAnalyzer runs specified analyzer for specified job
func (c *Client) RunAnalyzer(id string, data *JobBody) (*Job, error) {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(data)

	r, _, err := c.sendRequest("POST", analyzersURL+"/"+id+"/run", b)
	if err != nil {
		return nil, err
	}

	j := &Job{}
	if err := json.Unmarshal(r, j); err != nil {
		return nil, errors.New("Can't unmarshal Job")
	}

	return j, nil
}

//RunAnalyzerThenGetReport is a helper function that combines multiple functions to return JobReport
func (c *Client) RunAnalyzerThenGetReport(id string, data *JobBody, timeout string) (*JobReport, error) {
	j, err := c.RunAnalyzer(id, data)
	if err != nil {
		log.Printf("Failed to run analyzer %s", id)
		return nil, err
	}

	w, err := c.WaitForJob(j.ID, timeout)
	if err != nil {
		log.Printf("Failed to wait for a job %s", j.ID)
		return nil, err
	}

	r, err := c.GetJobReport(w.ID)
	if err != nil {
		log.Printf("Failed to get job report %s", w.ID)
		return nil, err
	}

	return r, nil
}

//AnalyzeData runs all analyzers suitable for a specified job and returns a channel
func (c *Client) AnalyzeData(data *JobBody, timeout string) (<-chan *JobReport, error) {
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
				log.Printf("Failed to process %s with %s", data.Data, an.Name)
			}
		}(a)
	}

	go func() {
		wg.Wait()
		close(reports)
	}()

	return reports, nil
}
