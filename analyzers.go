package gocortex

import (
	"bytes"
	"encoding/json"
	"errors"
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
