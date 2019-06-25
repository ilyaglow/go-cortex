package cortex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

const (
	libraryVersion = "2.4.1"

	// APIRoute represents a prefix path
	APIRoute = "api"

	userAgent     = "go-cortex/" + libraryVersion
	mediaType     = "application/json"
	errUnknownFmt = "http status: %s, unknown error"
	errMessageFmt = "http status: %s, %s: %s"
)

// TLP means Traffic Light Protocol.
type TLP uint8

// PAP means Permissible Actions Protocol.
type PAP uint8

// Type var is used instead of const because a pointer is needed when
// cortex.Task and cortex.FileTaskMeta structs are being marshalled. This will
// enable omitting the value and force Cortex itself to use default TLP and PAP
// for tasks: cortex.TLPAmber and cortex.PAPAmber.
var (
	// TLPWhite represents non-limited disclosure.
	TLPWhite TLP

	// TLPGreen limits disclosure, restricted to the community.
	TLPGreen TLP = 1

	// TLPAmber represents limited disclosure, restricted to participants’ organizations.
	TLPAmber TLP = 2

	// TLPRed is not for disclosure, restricted to participants only.
	TLPRed TLP = 3
)

var (
	// PAPWhite represents no restrictions in using information.
	// Source: https://github.com/MISP/misp-taxonomies/blob/master/PAP/machinetag.json#L24
	PAPWhite PAP

	// PAPGreen - active actions allowed.
	// Recipients may use PAP:GREEN information to ping the target,
	// block incoming/outgoing traffic from/to the target
	// or specifically configure honeypots to interact with the target
	// Source: https://github.com/MISP/misp-taxonomies/blob/master/PAP/machinetag.json#L19
	PAPGreen PAP = 1

	// PAPAmber - passive cross check.
	// Recipients may use PAP:AMBER information for conducting online checks,
	// like using services provided by third parties (e.g. VirusTotal),
	// or set up a monitoring honeypot.
	// Source: https://github.com/MISP/misp-taxonomies/blob/master/PAP/machinetag.json#L14
	PAPAmber PAP = 2

	// PAPRed - non-detectable actions only.
	// Recipients may not use PAP:RED information on the network.
	// Only passive actions on logs, that are not detectable from the outside.
	// Source: https://github.com/MISP/misp-taxonomies/blob/master/PAP/machinetag.json#L9
	PAPRed PAP = 3
)

// Client is used to communicate with Cortex API
type Client struct {
	Client    *http.Client
	BaseURL   *url.URL
	UserAgent string
	Opts      *ClientOpts
	PageSize  int

	Analyzers AnalyzerService
	Users     UserService
}

// ClientOpts represent options that are passed to client.
type ClientOpts struct {
	Auth       auth
	HTTPClient *http.Client
}

// errorMessage is the message that Cortex sends back to user when something
// went wrong.
type errorMessage struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NewClient bootstraps a client to interact with Cortex API
func NewClient(baseurl string, opts *ClientOpts) (*Client, error) {
	u, err := url.Parse(baseurl)
	if err != nil {
		return nil, err
	}

	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}

	c := &Client{
		Client:    opts.HTTPClient,
		BaseURL:   u,
		UserAgent: userAgent,
		Opts:      opts,
		PageSize:  100,
	}

	c.Analyzers = &AnalyzerServiceOp{client: c}
	c.Users = &UserServiceOp{client: c}

	return c, nil
}

// NewRequest creates an API request. A relative URL can be provided in urlStr,
// in which case it is resolved relative to the BaseURL of the Client.
// Relative URLs should always be specified without a preceding slash. If
// specified, the value pointed to by body is JSON encoded and included as the
// request body.
func (c *Client) NewRequest(method, urlStr string, body interface{}) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		err := enc.Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, err
	}

	if body != nil {
		req.Header.Set("Content-Type", mediaType)
	}
	req.Header.Set("Accept", mediaType)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	req.Header.Set("Authorization", c.Opts.Auth.Token())

	return req, nil
}

// NewFileRequest creates an API request with a file http form.
func (c *Client) NewFileRequest(method, urlStr string, body interface{}, fileName string, r io.Reader) (*http.Request, error) {
	if !strings.HasSuffix(c.BaseURL.Path, "/") {
		return nil, fmt.Errorf("BaseURL must have a trailing slash, but %q does not", c.BaseURL)
	}
	u, err := c.BaseURL.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	var w bytes.Buffer
	mpw := multipart.NewWriter(&w)
	fpart, err := mpw.CreateFormFile("attachment", fileName)
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(fpart, r)
	if err != nil {
		return nil, err
	}

	jpart, err := mpw.CreateFormField("_json")
	if err != nil {
		return nil, err
	}

	bb, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	_, err = jpart.Write(bb)
	if err != nil {
		return nil, err
	}

	if err := mpw.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), &w)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", mpw.FormDataContentType())
	req.Header.Set("Accept", mediaType)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	req.Header.Set("Authorization", c.Opts.Auth.Token())

	return req, nil
}

// Do sends an API request and returns the API response. The API response is
// JSON decoded and stored in the value pointed to by v, or returned as an
// error if an API error has occurred. If v implements the io.Writer
// interface, the raw response body will be written to v, without attempting to
// first decode it.
//
// The provided ctx must be non-nil. If it is canceled or times out,
// ctx.Err() will be returned.
func (c *Client) Do(ctx context.Context, req *http.Request, v interface{}) (*http.Response, error) {
	req = req.WithContext(ctx)

	resp, err := c.Client.Do(req)
	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		return nil, err
	}
	defer resp.Body.Close()

	err = checkResponse(resp)
	if err != nil {
		return resp, err
	}

	if v != nil {
		if w, ok := v.(io.Writer); ok {
			io.Copy(w, resp.Body)
		} else {
			decErr := json.NewDecoder(resp.Body).Decode(v)
			if decErr == io.EOF {
				decErr = nil // ignore EOF errors caused by empty response body
			}
			if decErr != nil {
				err = decErr
			}
		}
	}

	return resp, err
}

// checkResponse checks http response status code and returns an error if
// needed.
func checkResponse(r *http.Response) error {
	if r.StatusCode > 199 && r.StatusCode < 300 {
		return nil
	}

	var em errorMessage
	err := json.NewDecoder(r.Body).Decode(&em)
	if err != nil {
		return fmt.Errorf(errUnknownFmt, r.Status)
	}
	return fmt.Errorf(errMessageFmt, r.Status, em.Type, em.Message)
}
