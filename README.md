[![Codacy Badge](https://api.codacy.com/project/badge/Grade/1d131300c6864599b5335f2439b7e2d4)](https://www.codacy.com/app/ilyaglow/go-cortex?utm_source=github.com&utm_medium=referral&utm_content=ilyaglow/go-cortex&utm_campaign=badger)
[![GoDoc](https://godoc.org/github.com/ilyaglow/go-cortex?status.svg)](http://godoc.org/github.com/ilyaglow/go-cortex)
[![Build Status](https://travis-ci.org/ilyaglow/go-cortex.svg?branch=master)](https://travis-ci.org/ilyaglow/go-cortex)

## Usage example

```go
package main

import (
	"fmt"
	"log"

	"github.com/ilyaglow/go-cortex"
)

func main() {
	client := gocortex.NewClient("http://127.0.0.1:9000")

	jobs, err := client.ListJobs()
	if err != nil {
		panic("Failed to look up jobs")
	}
}
```
