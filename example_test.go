package cortex_test

import (
	"log"

	cortex "github.com/ilyaglow/go-cortex"
)

func Example() {
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
