package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/coder/wgtunnel/tunnelsdk"
)

// Read decodes JSON from the HTTP request into the value provided.
func Read(ctx context.Context, rw http.ResponseWriter, r *http.Request, value interface{}) bool {
	// TODO: tracing
	err := json.NewDecoder(r.Body).Decode(value)
	if err != nil {
		Write(ctx, rw, http.StatusBadRequest, tunnelsdk.Response{
			Message: "Request body must be valid JSON.",
			Detail:  err.Error(),
		})
		return false
	}

	return true
}

// Write outputs the given value as JSON to the response.
func Write(_ context.Context, rw http.ResponseWriter, status int, response interface{}) {
	// TODO: tracing
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)

	err := enc.Encode(response)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)

	_, err = rw.Write(buf.Bytes())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
}
