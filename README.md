[![GoDoc](https://godoc.org/github.com/ilyaglow/go-cortex?status.svg)](http://godoc.org/github.com/ilyaglow/go-cortex)
[![Build Status](https://travis-ci.org/ilyaglow/go-cortex.svg?branch=master)](https://travis-ci.org/ilyaglow/go-cortex)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1d131300c6864599b5335f2439b7e2d4)](https://www.codacy.com/app/ilyaglow/go-cortex?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ilyaglow/go-cortex&amp;utm_campaign=Badge_Grade)
[![Coverage Status](https://coveralls.io/repos/github/ilyaglow/go-cortex/badge.svg?branch=master)](https://coveralls.io/github/ilyaglow/go-cortex?branch=master)

## Usage example

```
go get -u github.com/ilyaglow/go-cortex
```

```go
package main

import (
	"log"

	"github.com/ilyaglow/go-cortex"
)

func main() {
	// Create a client struct
	client := gocortex.NewClient("http://127.0.0.1:9000")

	// Fill the JobBody struct
	j := &gocortex.JobBody{
		Data: "8.8.8.8",
		Attributes: gocortex.ArtifactAttributes{
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
