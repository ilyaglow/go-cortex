package cortex

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestListAnalyzers(t *testing.T) {
	client, mux, _, closer := setup()
	defer closer()

	mux.HandleFunc("/"+analyzersURL, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(analyzersJSON)
	})

	got, _, err := client.Analyzers.List(context.Background())
	if err != nil {
		t.Errorf("Analyzer.List returned error: %v", err)
	}
	if want := wantList; !reflect.DeepEqual(got, want) {
		t.Errorf("Analyzer.List = %+v, want %+v", got, want)
	}
}

func TestListByTypeAnalyzers(t *testing.T) {
	client, mux, _, closer := setup()
	defer closer()

	mux.HandleFunc("/"+analyzersByType+analyzerType, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(analyzersJSON)
	})

	got, _, err := client.Analyzers.ListByType(context.Background(), analyzerType)
	if err != nil {
		t.Errorf("Analyzer.ListByType returned error: %v", err)
	}
	if want := wantList; !reflect.DeepEqual(got, want) {
		t.Errorf("Analyzer.ListByType = %+v, want %+v", got, want)
	}
}

var analyzerType = "ip"

var analyzersJSON = []byte(`
[
  {
    "createdBy": "test1",
    "analyzerDefinitionId": "MaxMind_GeoIP_3_0",
    "dataTypeList": [
      "ip"
    ],
    "createdAt": 1527178197172,
    "name": "MaxMind_GeoIP_3_0",
    "description": "Use MaxMind to geolocate an IP address.",
    "jobCache": null,
    "_type": "analyzer",
    "_routing": "test",
    "_parent": "test",
    "_id": "c0b3f12a64d3fa2010ef2df4950d17b4",
    "_version": 1,
    "id": "c0b3f12a64d3fa2010ef2df4950d17b4",
    "version": "3.0",
    "author": "CERT-BDF",
    "url": "https://github.com/TheHive-Project/Cortex-Analyzers",
    "license": "AGPL-V3",
    "baseConfig": "MaxMind",
    "configuration": {
      "proxy_http": null,
      "proxy_https": null,
      "auto_extract_artifacts": false,
      "check_tlp": true,
      "max_tlp": 3
    }
  }
]
`)

var config = map[string]interface{}{
	"proxy_http":             nil,
	"proxy_https":            nil,
	"auto_extract_artifacts": false,
	"check_tlp":              true,
	"max_tlp":                float64(3),
}

var wantList = []Analyzer{
	{
		Author:        "CERT-BDF",
		BaseConfig:    "MaxMind",
		Configuration: config,
		CreatedAt:     1527178197172,
		CreatedBy:     "test1",
		DataTypeList:  []string{"ip"},
		DefinitionID:  "MaxMind_GeoIP_3_0",
		Description:   "Use MaxMind to geolocate an IP address.",
		ID:            "c0b3f12a64d3fa2010ef2df4950d17b4",
		JobCache:      nil,
		License:       "AGPL-V3",
		Name:          "MaxMind_GeoIP_3_0",
		Rate:          0,
		RateUnit:      "",
		URL:           "https://github.com/TheHive-Project/Cortex-Analyzers",
		UpdatedAt:     0,
		UpdatedBy:     "",
		Version:       "3.0",
	},
}
