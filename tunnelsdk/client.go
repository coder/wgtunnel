package tunnelsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/xerrors"
)

// New creates a tunneld client for the provided URL.
func New(serverURL *url.URL) *Client {
	return &Client{
		HTTPClient: &http.Client{},
		URL:        serverURL,
	}
}

// Client provides HTTP methods for the tunneld API and a full wireguard tunnel
// client implementation.
type Client struct {
	HTTPClient *http.Client
	URL        *url.URL
}

// Request performs an HTTP request with the body provided. The caller is
// responsible for closing the response body.
func (c *Client) Request(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	serverURL, err := c.URL.Parse(path)
	if err != nil {
		return nil, xerrors.Errorf("parse url: %w", err)
	}

	var buf bytes.Buffer
	if body != nil {
		if data, ok := body.([]byte); ok {
			buf = *bytes.NewBuffer(data)
		} else {
			// Assume JSON if not bytes.
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			err = enc.Encode(body)
			if err != nil {
				return nil, xerrors.Errorf("encode body: %w", err)
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, serverURL.String(), &buf)
	if err != nil {
		return nil, xerrors.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("do: %w", err)
	}
	return resp, err
}

// readBodyAsError reads the response body as tunnelsdk.Error type for easily
// reading the error message.
func readBodyAsError(res *http.Response) error {
	if res == nil {
		return xerrors.Errorf("no body returned")
	}
	defer res.Body.Close()
	contentType := res.Header.Get("Content-Type")

	var method, u string
	if res.Request != nil {
		method = res.Request.Method
		if res.Request.URL != nil {
			u = res.Request.URL.String()
		}
	}

	resp, err := io.ReadAll(res.Body)
	if err != nil {
		return xerrors.Errorf("read body: %w", err)
	}

	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mimeType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	if mimeType != "application/json" {
		if len(resp) > 1024 {
			resp = append(resp[:1024], []byte("...")...)
		}
		if len(resp) == 0 {
			resp = []byte("no response body")
		}
		return &Error{
			statusCode: res.StatusCode,
			Response: Response{
				Message: "unexpected non-JSON response",
				Detail:  string(resp),
			},
		}
	}

	var m Response
	err = json.NewDecoder(bytes.NewBuffer(resp)).Decode(&m)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return &Error{
				statusCode: res.StatusCode,
				Response: Response{
					Message: "empty response body",
				},
			}
		}
		return xerrors.Errorf("decode body: %w", err)
	}
	if m.Message == "" {
		if len(resp) > 1024 {
			resp = append(resp[:1024], []byte("...")...)
		}
		m.Message = fmt.Sprintf("unexpected status code %d, response has no message", res.StatusCode)
		m.Detail = string(resp)
	}

	return &Error{
		Response:   m,
		statusCode: res.StatusCode,
		method:     method,
		url:        u,
	}
}

// Error represents an unaccepted or invalid request to the API.
type Error struct {
	Response

	statusCode int
	method     string
	url        string
}

func (e *Error) StatusCode() int {
	return e.statusCode
}

func (e *Error) Friendly() string {
	return e.Message
}

func (e *Error) Error() string {
	var builder strings.Builder
	if e.method != "" && e.url != "" {
		_, _ = fmt.Fprintf(&builder, "%v %v: ", e.method, e.url)
	}
	_, _ = fmt.Fprintf(&builder, "unexpected status code %d: %s", e.statusCode, e.Message)
	if e.Detail != "" {
		_, _ = fmt.Fprintf(&builder, "\n\tError: %s", e.Detail)
	}

	return builder.String()
}
