package cortex

import (
	"bytes"
	"reflect"
	"testing"
)

var sampleConfig = []byte(`
{
    "data": "d41d8cd98f00b204e9800998ecf8427e",
    "dataType": "hash",
    "tlp": 0,
    "config": {
        "key": "1234567890abcdef",
        "max_tlp": 3,
        "check_tlp": true,
        "service": "GetReport"
    },
    "proxy": {
        "http": "http://myproxy:8080",
        "https": "https://myproxy:8080"
    }
}
`)

var sampleReader = bytes.NewReader(sampleConfig)

func TestGetters(t *testing.T) {
	ai, err := parseInput(sampleReader)
	if err != nil {
		t.Fatal(err)
	}

	s, err := ai.Config.GetString("service")
	if err != nil {
		t.Fatal(err)
	}

	if s != "GetReport" {
		t.Fatalf("need GetReport, got %s", s)
	}

	f, err := ai.Config.GetFloat("max_tlp")
	if err != nil {
		t.Fatal(err)
	}

	if f != 3 {
		t.Fatalf("need 3, got %f", f)
	}

	b, err := ai.Config.GetBool("check_tlp")
	if err != nil {
		t.Fatal(err)
	}

	if b != true {
		t.Fatalf("need true, got %t", b)
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

func artifactsToMap(as []Artifact) map[string][]string {
	m := make(map[string][]string)

	for i := range as {
		m[as[i].Attributes.DataType] = append(m[as[i].Attributes.DataType], as[i].Data)
	}

	return m
}
