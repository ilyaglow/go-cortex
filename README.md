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

	fmt.Printf("%v\n", jobs)

	analyzers, _ := client.ListAnalyzers("ip")
	fmt.Printf("%v\n", analyzers)

	a, _ := client.GetAnalyzer("MaxMind_GeoIP_3_0")
	fmt.Printf("%v\n", a)

	j := &gocortex.JobBody{
		Data: "8.8.8.8",
		Attributes: gocortex.ArtifactAttributes{
			DataType: "ip",
			TLP:      2,
		},
	}

	job, _ := client.RunAnalyzer(a.ID, j)
	fmt.Printf("%v\n", job)

	jobResult, _ := client.WaitForJob(job.ID, "1minute")
	fmt.Printf("%v\n", jobResult)

	jobReport, _ := client.GetJobReport(jobResult.ID)
	fmt.Printf("%v\n", jobReport)
}
```
