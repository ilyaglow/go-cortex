package cortex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/asaskevich/govalidator"
)

const (
	// TxSafe is a safe taxonomy level
	TxSafe = "safe"

	// TxInfo is an info taxonomy level
	TxInfo = "info"

	// TxSuspicious is a suspicious taxonomy level
	TxSuspicious = "suspicious"

	// TxMalicious is a malicious taxonomy level
	TxMalicious = "malicious"
)

var (
	domain = `([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z]{1}[a-zA-Z]{0,62})+[\._]?`
	// inspired by govalidator.CreditCard
	rxCC     = regexp.MustCompile("(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})")
	rxDomain = regexp.MustCompile(domain)
	// inspired by govalidator.Email
	rxEmail          = regexp.MustCompile("(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@" + domain)
	rxHash           = regexp.MustCompile(`([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})`)
	rxIPv4           = regexp.MustCompile(`((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.)?){1}`)
	rxIPv6           = regexp.MustCompile(`\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*`)
	rxRegistryKey    = regexp.MustCompile(`(HKEY|HKLM|HKCU|HKCR|HKCC)[\\a-zA-Z0-9]+`)
	rxURL            = regexp.MustCompile(govalidator.URLSchema + govalidator.URLUsername + `?` + `((` + govalidator.URLIP + `|(\[` + govalidator.IP + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + govalidator.URLSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + govalidator.URLPort + `?` + govalidator.URLPath + `?`)
	rxUserAgent      = regexp.MustCompile(`Mozilla/[0-9]\.[0-9] \(([A-Za-z0-9 \/._]+;){1,3} ([A-Za-z0-9 \/.:_]+){0,2}\)( ([A-Za-z0-9 \/.]+){1} \(KHTML, like Gecko\)){0,1} ([A-Za-z0-9 \/.]+){2,3}`)
	rxBitcoinAddress = regexp.MustCompile(`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`)
)

// Rxs represents map of regexes
var Rxs = map[string]*regexp.Regexp{
	"cc":              rxCC,
	"ipv4":            rxIPv4,
	"ipv6":            rxIPv6,
	"domain":          rxDomain,
	"email":           rxEmail,
	"hash":            rxHash,
	"registry":        rxRegistryKey,
	"url":             rxURL,
	"user-agent":      rxUserAgent,
	"bitcoin-address": rxBitcoinAddress,
}

type cfg map[string]interface{}

// JobInput is used to track failed jobs and work with analyzer's input
type JobInput struct {
	DataType    string            `json:"dataType"`
	TLP         int               `json:"tlp,omitempty"`
	Data        string            `json:"data,omitempty"`
	File        string            `json:"file,omitempty"`
	FileName    string            `json:"filename,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Config      cfg               `json:"config,omitempty"`
	Message     string            `json:"message,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
}

// ExtractedArtifact is used for artifacts with slightly different structure
type ExtractedArtifact struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

//AnalyzerReport is the report that analyzer app should return in case everything is okay
type AnalyzerReport struct {
	Artifacts  []ExtractedArtifact `json:"artifacts"`
	FullReport interface{}         `json:"full"`
	Success    bool                `json:"success"`
	Summary    *Summary            `json:"summary"`
}

// AnalyzerError is the report that analyzer app should return in case something went wrong
type AnalyzerError struct {
	Success      bool      `json:"success"`
	ErrorMessage string    `json:"errorMessage"`
	Input        *JobInput `json:"input"`
}

// PrintError returns unsuccessful Report with an error message
func (j *JobInput) PrintError(err error) {
	r := &AnalyzerError{
		Success:      false,
		ErrorMessage: err.Error(),
		Input:        j,
	}

	body, merr := json.Marshal(r)
	if merr != nil {
		log.Fatal(merr)
	}

	fmt.Print(string(body))
	os.Exit(1)
}

// PrintReport constructs Report by raw body and taxonomies
func (j *JobInput) PrintReport(body interface{}, taxes []Taxonomy) {
	mb, err := json.Marshal(body)
	if err != nil {
		log.Fatal(err)
	}

	artifacts := make([]ExtractedArtifact, 0)
	if j.Config.NeedExtractArtifacts() {
		artifacts = ExtractArtifacts(string(mb))
	}

	r := &AnalyzerReport{
		Success:    true,
		Artifacts:  artifacts,
		FullReport: body,
		Summary:    &Summary{taxes},
	}
	b, err := json.Marshal(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(b))
	os.Exit(0)
}

func (j *JobInput) allowedTLP() bool {
	// if maxtlp is not set, make it to maximum
	maxtlp, err := j.Config.GetFloat("max_tlp")
	if err != nil {
		maxtlp = 3
	}

	if j.TLP > int(maxtlp) {
		return false
	}
	return true
}

// ExtractArtifacts extracts all artifacts from report string
func ExtractArtifacts(body string) []ExtractedArtifact {
	ars := []ExtractedArtifact{}
	ma := make(map[string]bool)
	for t, r := range Rxs {
		res := r.FindAllString(body, -1)
		if res == nil {
			continue
		}

		for i := range res {
			if _, ok := ma[res[i]]; ok {
				continue
			}

			ma[res[i]] = true
			ars = append(ars, ExtractedArtifact{
				Value: res[i],
				Type:  t,
			})
		}
	}
	return ars
}

// NeedExtractArtifacts checks if user wants to extract artifacts
func (c cfg) NeedExtractArtifacts() bool {
	res, err := c.GetBool("auto_extract_artifacts")
	if err != nil {
		return false
	}

	return res
}

// client returns proxified *http.Client using http proxy, specified by a user
func (c cfg) client() *http.Client {
	proxy, ok := c["Proxy"]
	if !ok {
		return http.DefaultClient
	}

	mProxy := proxy.(map[string]string)
	proxyURL, err := url.Parse(mProxy["http"])
	if err != nil {
		return http.DefaultClient
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
}

// GetString is a getter for string type
func (c cfg) GetString(key string) (string, error) {
	var (
		res string
		err error
		val interface{}
		ok  bool
	)

	if val, ok = c[key]; !ok {
		return "", fmt.Errorf("Not such key: %s", key)
	}

	switch val.(type) {
	case string:
		res = val.(string)
	default:
		res = ""
		err = fmt.Errorf("Wrong type chosen for key %s: (%T)", key, val)
	}

	return res, err
}

// GetFloat is a getter for float64 type
func (c cfg) GetFloat(key string) (float64, error) {
	var (
		res float64
		err error
		val interface{}
		ok  bool
	)

	if val, ok = c[key]; !ok {
		return 0, fmt.Errorf("Not such key: %s", key)
	}

	switch val.(type) {
	case float64:
		res = val.(float64)
	default:
		res = 0
		err = fmt.Errorf("Wrong type chosen for key %s: (%T)", key, val)
	}

	return res, err
}

// GetBool is a getter for bool type
func (c cfg) GetBool(key string) (bool, error) {
	var (
		res bool
		err error
		val interface{}
		ok  bool
	)

	if val, ok = c[key]; !ok {
		return false, fmt.Errorf("Not such key: %s", key)
	}

	switch val.(type) {
	case bool:
		res = val.(bool)
	default:
		res = false
		err = fmt.Errorf("Wrong type chosen for key %s: (%T)", key, val)
	}
	return res, err
}

// NewInput grabs stdin and bootstraps *JobInput and *http.Client
func NewInput() (*JobInput, *http.Client, error) {
	in, err := parseInput(os.Stdin)
	if err != nil {
		return nil, http.DefaultClient, err
	}

	v, err := in.Config.GetBool("check_tlp")
	if err != nil {
		return in, in.Config.client(), nil // if check_tlp is not found do not check for it
	}

	if v && !in.allowedTLP() {
		in.PrintError(errors.New("TLP is higher than allowed"))
		return nil, nil, nil
	}

	return in, in.Config.client(), nil
}

func parseInput(f io.Reader) (*JobInput, error) {
	var j JobInput
	dec := json.NewDecoder(f)

	for {
		err := dec.Decode(&j)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			log.Println(err)
			return nil, err
		}
	}

	return &j, nil
}
