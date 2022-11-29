package httpmw

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/httprate"

	"github.com/coder/wgtunnel/tunneld/httpapi"
	"github.com/coder/wgtunnel/tunnelsdk"
)

// RateLimit returns a handler that limits requests based on IP.
func RateLimit(count int, window time.Duration) func(http.Handler) http.Handler {
	if count <= 0 {
		return func(handler http.Handler) http.Handler {
			return handler
		}
	}

	return httprate.Limit(
		count,
		window,
		httprate.WithKeyByIP(),
		httprate.WithLimitHandler(func(rw http.ResponseWriter, r *http.Request) {
			httpapi.Write(r.Context(), rw, http.StatusTooManyRequests, tunnelsdk.Response{
				Message: fmt.Sprintf("You've been rate limited for sending more than %v requests in %v.", count, window),
			})
		}),
	)
}
