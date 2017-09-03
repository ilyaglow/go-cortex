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
