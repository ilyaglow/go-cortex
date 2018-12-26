package cortex

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestUnauthorized(t *testing.T) {
	client, mux, _, closer := setup()
	defer closer()

	mux.HandleFunc("/"+currentUser, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(unauthorizedJSON)
	})

	_, _, got := client.Users.Current(context.Background())
	if got == nil {
		t.Error("test request Users.Current hasn't returned an error")
	}
	if want := errUnauthorized; !reflect.DeepEqual(got, want) {
		t.Errorf("error %+v, want %+v", got, want)
	}

}

var (
	unauthorizedJSON = []byte(`
{
	"type":"AuthenticationError",
	"message":"Authentication failure"
}
`)

	errUnauthorized = fmt.Errorf(
		errMessageFmt,
		"401 Unauthorized",
		"AuthenticationError",
		"Authentication failure",
	)
)
