package gocortex

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

//Client used to deal API location and basic auth (in future)
type Client struct {
	//Location is the Cortex base URL
	Location string

	//Client used to communicate with the API
	Client *http.Client
}

//NewClient bootstraps Client to use later
func NewClient(location string) *Client {
	return &Client{
		Location: location,
		Client:   http.DefaultClient,
	}
}

//sendRequest used to abstract http requests from higher level functions
//returns response body and status code
func (c *Client) sendRequest(method string, path string, reqBody *bytes.Buffer) ([]byte, int, error) {
	var req *http.Request
	var err error

	if reqBody != nil {
		req, err = http.NewRequest(method, c.Location+path, reqBody)
		if err != nil {
			return nil, 0, err
		}
	} else {
		req, err = http.NewRequest(method, c.Location+path, nil)
		if err != nil {
			return nil, 0, err
		}
	}

	req.Header.Add("Content-Type", `application/json`)

	res, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)

	return body, res.StatusCode, nil
}
