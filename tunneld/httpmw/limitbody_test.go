package httpmw_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/wgtunnel/tunneld/httpmw"
	"github.com/stretchr/testify/require"
)

func TestLimitBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name         string
		Limit        int64
		Size         int
		LimitReached bool
	}{
		{
			Name:         "under",
			Limit:        1024,
			Size:         512,
			LimitReached: false,
		},
		{
			Name:         "under-by-one",
			Limit:        1024,
			Size:         1023,
			LimitReached: false,
		},
		{
			Name:         "exact",
			Limit:        1024,
			Size:         1024,
			LimitReached: true,
		},
		{
			Name:         "over",
			Limit:        1024,
			Size:         1025,
			LimitReached: true,
		},
		{
			Name:         "default-under",
			Limit:        1 << 20,
			Size:         1 << 19,
			LimitReached: false,
		},
		{
			Name:         "default-over",
			Limit:        1 << 20,
			Size:         1<<20 + 1,
			LimitReached: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			var buf bytes.Buffer
			buf.Grow(test.Size)
			for i := 0; i < test.Size; i++ {
				err := buf.WriteByte('1')
				require.NoError(t, err, "expected to write byte to buffer successfully")
			}

			req := httptest.NewRequest("POST", "/", &buf)
			middleware := httpmw.LimitBody(test.Limit)

			handlerCalled := false

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// Read as much as we can from the body, discarding output
				written, err := io.Copy(io.Discard, req.Body)
				if test.LimitReached {
					require.ErrorIs(t, err, httpmw.ErrLimitReached, "expected stream to return ErrLimitReached")
					require.EqualValues(t, test.Limit, written, "expect that the amount of data copied matches the limit")
				} else {
					require.NoError(t, err, "no error should occur")
					require.EqualValues(t, test.Size, written, "expect that the amount of data copied matches the input size")
				}

				handlerCalled = true
			})

			middleware(nextHandler).ServeHTTP(httptest.NewRecorder(), req)
			require.True(t, handlerCalled, "expected handler to be invoked")
		})
	}
}
