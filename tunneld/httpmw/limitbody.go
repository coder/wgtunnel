package httpmw

import (
	"io"
	"net/http"

	"golang.org/x/xerrors"
)

var ErrLimitReached = xerrors.Errorf("i/o limit reached")

// LimitReader is like io.LimitReader except that it returns ErrLimitReached
// when the limit has been reached.
type LimitReader struct {
	Limit int64
	N     int64
	R     io.Reader
}

func (l *LimitReader) Reset(n int64) {
	l.N = 0
	l.Limit = n
}

func (l *LimitReader) Read(p []byte) (int, error) {
	if l.N >= l.Limit {
		return 0, ErrLimitReached
	}

	if int64(len(p)) > l.Limit-l.N {
		p = p[:l.Limit-l.N]
	}

	n, err := l.R.Read(p)
	l.N += int64(n)
	return n, err
}

type LimitedBody struct {
	R        *LimitReader
	original io.ReadCloser
}

func (r LimitedBody) Read(p []byte) (n int, err error) {
	return r.R.Read(p)
}

func (r LimitedBody) Close() error {
	return r.original.Close()
}

func SetBodyLimit(r *http.Request, n int64) {
	if body, ok := r.Body.(LimitedBody); ok {
		body.R.Reset(n)
	} else {
		r.Body = LimitedBody{
			R:        &LimitReader{R: r.Body, Limit: n},
			original: r.Body,
		}
	}
}

func LimitBody(n int64) func(h http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			SetBodyLimit(r, n)
			next.ServeHTTP(w, r)
		})
	}
}
