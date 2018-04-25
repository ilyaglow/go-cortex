[![GoDoc](https://godoc.org/github.com/ilyaglow/go-cortex?status.svg)](http://godoc.org/github.com/ilyaglow/go-cortex)
[![Build Status](https://travis-ci.org/ilyaglow/go-cortex.svg?branch=master)](https://travis-ci.org/ilyaglow/go-cortex)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1d131300c6864599b5335f2439b7e2d4)](https://www.codacy.com/app/ilyaglow/go-cortex?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ilyaglow/go-cortex&amp;utm_campaign=Badge_Grade)
[![Coverage Status](https://coveralls.io/repos/github/ilyaglow/go-cortex/badge.svg?branch=master)](https://coveralls.io/github/ilyaglow/go-cortex?branch=master)

## Usage example

```
go get -u github.com/ilyaglow/go-cortex
```

### Analyze simple string type observable

```go
package main

import (
	"log"

	"github.com/ilyaglow/go-cortex"
)

func main() {
	// Create a client struct
	client := cortex.NewClient("http://127.0.0.1:9000")

	// Fill the Artifact struct
	j := &cortex.Artifact{
		Data: "8.8.8.8",
		Attributes: cortex.ArtifactAttributes{
			DataType: "ip",
			TLP:      3,
		},
	}

	// Run all analyzers over it with 1 minute timeout
	reports, err := client.AnalyzeData(j, "1minute")
	if err != nil {
		panic(err)
	}
	
	// Iterate over channel with reports and get taxonomies
	for m := range reports {
		txs := m.Taxonomies()
		for _, t := range txs {
			log.Printf("\"%s:%s\"=\"%s\"", t.Namespace, t.Predicate, t.Value)
		}
	}
}
```

### Analyze file type observable

Basically, any type that implements `io.Reader` could be analyzed.

```go
package main

import (
	"log"
	"os"

	"github.com/ilyaglow/go-cortex"
)

func main() {

	client := cortex.NewClient("http://127.0.0.1:9000")

	// Open the file
	fname := "filename.exe"
	f, err := os.Open(fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	freports, err := client.AnalyzeData(&cortex.FileArtifact{
		FileArtifactMeta: cortex.FileArtifactMeta{
			DataType: "file",
			TLP:      3,
		},
		FileName: fname,
		Reader:   f,
	}, "5minutes")
	if err != nil {
		panic(err)
	}

	for m := range freports {
		if m.Status == "Failure" {
			log.Printf("%s failed with an error: %s\n", m.AnalyzerID, m.Report.ErrorMessage)
			continue
		}

		log.Println(m.Report.FullReport)
	}
}
```

# Write your own analyzer

```golang
package main

import (
	"log"
	"strconv"

	"github.com/ilyaglow/go-cortex"
)

// Report is a sample analyzer report
type Report struct {
	Field   string   `json:"field,omitempty"`
	Results []string `json:"results,omitempty"`
	Status  bool     `json:"status,omitempty"`
}

func main() {
	// Grab stdin to JobInput structure
	input, err := cortex.NewInput()
	if err != nil {
		log.Fatal(err)
	}

	// Get url parameter from analyzer config
	url, err := input.Config.GetString("url")
	if err != nil {
		// Report an error if something went wrong
		cortex.SayError(input, err.Error())
	}

	// You get somehow report struct from JobInput.Data
	rep, err := Do(input.Data, url)
	if err != nil {
		cortex.SayError(input, err.Error())
	}

	// Make taxonomies
	var txs []cortex.Taxonomy
	namespace := "AnalyzerName"
	predicate := "Predicate"
	if len(rep.Results) == 0 {
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     "safe",
			Value:     "0",
		})
	} else {
		txs = append(txs, cortex.Taxonomy{
			Namespace: namespace,
			Predicate: predicate,
			Level:     "suspicious",
			Value:     strconv.FormatInt(int64(len(rep.Results[0])), 10),
		})
	}

	// Report accept marshallable struct and taxonomies
	cortex.SayReport(rep, txs)
}

// Do represents analyzing data
func Do(input string, u string) (*Report, error) {
	return &Report{
		Field:   "some",
		Results: []string{"domain.com", "127.0.0.1", "email@domain.com"},
		Status:  true,
	}, nil
}
```

You can see a real world examples at [https://github.com/ilyaglow/go-cortex-analyzers](https://github.com/ilyaglow/go-cortex-analyzers).
