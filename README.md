[![GoDoc](https://godoc.org/github.com/ilyaglow/go-cortex?status.svg)](http://godoc.org/github.com/ilyaglow/go-cortex)
[![Build Status](https://travis-ci.org/ilyaglow/go-cortex.svg?branch=v2)](https://travis-ci.org/ilyaglow/go-cortex)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1d131300c6864599b5335f2439b7e2d4)](https://www.codacy.com/app/ilyaglow/go-cortex?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ilyaglow/go-cortex&amp;utm_campaign=Badge_Grade)
[![Coverage Status](https://coveralls.io/repos/github/ilyaglow/go-cortex/badge.svg?branch=v2)](https://coveralls.io/github/ilyaglow/go-cortex?branch=v2)

[WIP] Cortex v2 client library
------------------------------

This version is not compatible with Cortex v1 version.

I tried to avoid limitations, pitfalls and antipatterns from the previous version, so I even changed a whole approach in a couple places. Hope you'll enjoy it.

## Usage example

Get latest library
```
go get -u github.com/ilyaglow/go-cortex
```

### Simply run analyzer for an observable

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ilyaglow/go-cortex"
)

func main() {
	crtx, err := cortex.NewClient("http://127.0.0.1:9001/", &cortex.ClientOpts{
		Auth: &cortex.APIAuth{
			APIKey: "YOUR-API-KEY",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	rep, err := crtx.Analyzers.Run(context.Background(), "MaxMind_GeoIP_3_0", &cortex.Task{
		Data:     "1.1.1.1",
		DataType: "ip",
		TLP:      &cortex.TLPGreen,
	}, time.Minute*5)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%v\n", rep)
}
```

### Aggregated analysis of an observable

Could be used to analyze an observable by all analyzers that can work with it's data type at once. Previous implementation used a channel approach that seemed to me very limiting.

Now you can use callback functions when analyzer returns a report or an error.

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/ilyaglow/go-cortex"
)

func main() {
	crtx, err := cortex.NewClient("http://127.0.0.1:9001/", &cortex.ClientOpts{
		Auth: &cortex.APIAuth{
			APIKey: "YOUR-API-KEY",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	task := &cortex.Task{
		Data: "1.1.1.1",
		DataType: "ip",
		TLP: &cortex.TLPWhite,
	}

	// Create new MultiRun struct
	mul := crtx.Analyzers.NewMultiRun(context.Background(), 5*time.Minute)
	mul.OnReport = func(r *cortex.Report) {
		log.Println(r)
	}
	mul.OnError = func(e error, o cortex.Observable, a *cortex.Analyzer) {
		log.Printf("Cortex analyzer %s failed on data %s with an error: %s", a.Name, o.Description(), e.Error())
	}

	// Actually run the analysis
	err = mul.Do(task)
	if err != nil {
		log.Fatal(err)
	}
}
```
