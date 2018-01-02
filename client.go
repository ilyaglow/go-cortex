package gocortex

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// Client is used to deal with the API location and basic auth (in the future)
type Client struct {
	// Location is the Cortex base URL
	Location string

	// Client is used to communicate with the API
	Client *http.Client

	// Debug mode
	Debug bool
}

// NewClient bootstraps a Client
// If there is a need to change the http.DefaultClient you should construct a Client struct by yourself
func NewClient(location string) *Client {
	return &Client{
		Location: location,
		Client:   http.DefaultClient,
		Debug:    false,
	}
}

// sendRequest is used to abstract http requests from the higher level functions
// returns response body and status code
func (c *Client) sendRequest(method string, path string, reqBody *[]byte) ([]byte, int, error) {
	var req *http.Request
	var err error
	var loc string

	loc = c.Location + path

	if reqBody != nil {
		c.log(fmt.Sprintf("%s %s, request body %s", method, path, string(*reqBody)))

		req, err = http.NewRequest(method, loc, bytes.NewBuffer(*reqBody))
		if err != nil {
			return nil, 0, err
		}
	} else {
		c.log(fmt.Sprintf("%s %s", method, path))

		req, err = http.NewRequest(method, loc, nil)
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
	c.log(fmt.Sprintf("Response status code: %d, data: %s", res.StatusCode, string(body)))

	return body, res.StatusCode, nil
}

// log is used to print debug messages
func (c *Client) log(s string) {
	if c.Debug == true {
		log.Println(s)
	}
}
