package cortex

import (
	"bytes"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

var sampleConfig = []byte(`
{
    "data": "d41d8cd98f00b204e9800998ecf8427e",
    "dataType": "hash",
    "tlp": 0,
	"pap": 1,
    "config": {
        "key": "1234567890abcdef",
        "max_tlp": 3,
        "max_pap": 2,
        "check_tlp": true,
        "check_pap": true,
        "service": "GetReport",
        "proxy_http": "http://user:pass@myproxy:8080",
        "proxy_https": "https://user:pass@myproxy:8080",
        "proxy": {
            "http": "http://myproxy:8080",
            "https": "https://myproxy:8080"
        }
    }
}
`)

func TestGetters(t *testing.T) {
	var getterTests = []struct {
		key   string
		value interface{}
		err   error
	}{
		{"service", "GetReport", nil},
		{"check_tlp", true, nil},
		{"check_pap", true, nil},
		{"max_tlp", 3.0, nil},
		{"max_pap", 2.0, nil},
		{"nonexistent", false, errors.New("Not such key: nonexistent")},
		{"proxy_http", "http://user:pass@myproxy:8080", nil},
	}

	ai, err := parseInput(bytes.NewReader(sampleConfig))
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range getterTests {
		var (
			val interface{}
			err error
		)

		switch p.value.(type) {
		case string:
			val, err = ai.Config.GetString(p.key)
		case float64:
			val, err = ai.Config.GetFloat(p.key)
		case bool:
			val, err = ai.Config.GetBool(p.key)
		}

		if !reflect.DeepEqual(p.err, err) {
			t.Fatal(err)
		}

		if val != p.value {
			t.Fatalf("need %v, got %v", p.value, val)
		}
	}
}

func TestExtractArtifacts(t *testing.T) {
	var patternsTest = []struct {
		report    string
		typedData map[string][]string
	}{
		{`{"report":{"ip":"8.8.8.8"}}`, map[string][]string{"ipv4": []string{"8.8.8.8"}}},
		{`{"report":{"domain":"test.com"}}`, map[string][]string{"domain": []string{"test.com"}}},
		{`{"report":{"email":"name@domainname.com"}}`, map[string][]string{"email": []string{"name@domainname.com"}, "domain": []string{"domainname.com"}}},
		{`{"report":{"url":"https://testdomain.com/handler?parameter=value`, map[string][]string{"domain": []string{"testdomain.com"}, "url": []string{"https://testdomain.com/handler?parameter=value"}}},
		{`{"report":{"hash1":"ba1f2511fc30423bdbb183fe33f3dd0f", "hash2":"a8fdc205a9f19cc1c7507a60c4f01b13d11d7fd0", "hash3": "181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b"}}`, map[string][]string{"hash": []string{"ba1f2511fc30423bdbb183fe33f3dd0f", "a8fdc205a9f19cc1c7507a60c4f01b13d11d7fd0", "181210f8f9c779c26da1d9b2075bde0127302ee0e3fca38c9a83f5b1dd8e5d3b"}}},
		{`{"report":{"ipv6":"2a00:1450:4011:809::1002"}}`, map[string][]string{"ipv6": []string{"2a00:1450:4011:809::1002"}}},
		{`{"report":{"useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"}}`, map[string][]string{"user-agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"}}},
		{`{"report":{"bitcoinaddr":"12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"}}`, map[string][]string{"bitcoin-address": []string{"12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"}}},
		{`{"report":{"ccnum":"38520000023237"}}`, map[string][]string{"cc": []string{"38520000023237"}}},
	}

	for _, p := range patternsTest {
		as := ExtractArtifacts(p.report)
		am := artifactsToMap(as)

		if !reflect.DeepEqual(p.typedData, am) {
			t.Fatalf("need %v, got %v", p.typedData, am)
		}
	}
}

func artifactsToMap(as []ExtractedArtifact) map[string][]string {
	m := make(map[string][]string)

	for i := range as {
		m[as[i].Type] = append(m[as[i].Type], as[i].Value)
	}

	return m
}

func TestProxyHandling(t *testing.T) {
	ai, err := parseInput(bytes.NewReader(sampleConfig))
	if err != nil {
		t.Fatal(err)
	}

	client := ai.Config.httpClient()
	if reflect.DeepEqual(client, http.DefaultClient) {
		t.Fatalf("failed to bootstrap proxy server %v", client)
	}
}
