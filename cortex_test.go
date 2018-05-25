package cortex

import (
	"net/http"
	"net/http/httptest"
)

func setup() (client *Client, mux *http.ServeMux, serverURL string, teardown func()) {
	mux = http.NewServeMux()
	server := httptest.NewServer(mux)

	client, _ = NewClient(server.URL+"/", &ClientOpts{
		Auth: &APIAuth{
			APIKey: "dummy-key",
		},
	})

	client.PageSize = 100

	return client, mux, server.URL, server.Close
}
