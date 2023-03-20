package httpmw

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/httprate"

	"cdr.dev/slog"
	"github.com/coder/wgtunnel/tunneld/httpapi"
	"github.com/coder/wgtunnel/tunnelsdk"
)

type RateLimitConfig struct {
	Log slog.Logger

	// Count of the amount of requests allowed in the Window. If the Count is
	// zero, the rate limiter is disabled.
	Count  int
	Window time.Duration

	// RealIPHeader is the header to use to get the real IP address of the
	// request. If this is empty, the request's RemoteAddr is used.
	RealIPHeader string
}

// RateLimit returns a handler that limits requests based on IP.
func RateLimit(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if cfg.Count <= 0 {
		return func(handler http.Handler) http.Handler {
			return handler
		}
	}

	var logMissingHeaderOnce sync.Once

	return httprate.Limit(
		cfg.Count,
		cfg.Window,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			if cfg.RealIPHeader != "" {
				val := r.Header.Get(cfg.RealIPHeader)
				if val != "" {
					val = strings.TrimSpace(strings.Split(val, ",")[0])
					return canonicalizeIP(val), nil
				}

				logMissingHeaderOnce.Do(func() {
					cfg.Log.Warn(r.Context(), "real IP header not found or invalid on request", slog.F("header", cfg.RealIPHeader), slog.F("value", val))
				})
			}

			return httprate.KeyByIP(r)
		}),
		httprate.WithLimitHandler(func(rw http.ResponseWriter, r *http.Request) {
			httpapi.Write(r.Context(), rw, http.StatusTooManyRequests, tunnelsdk.Response{
				Message: fmt.Sprintf("You've been rate limited for sending more than %v requests in %v.", cfg.Count, cfg.Window),
			})
		}),
	)
}

// canonicalizeIP returns a form of ip suitable for comparison to other IPs.
// For IPv4 addresses, this is simply the whole string.
// For IPv6 addresses, this is the /64 prefix.
//
// This function is taken directly from go-chi/httprate:
// https://github.com/go-chi/httprate/blob/0ea2148d09a46ae62efcad05b70d87418d8e4f43/httprate.go#L111
func canonicalizeIP(ip string) string {
	isIPv6 := false
	// This is how net.ParseIP decides if an address is IPv6
	// https://cs.opensource.google/go/go/+/refs/tags/go1.17.7:src/net/ip.go;l=704
	for i := 0; !isIPv6 && i < len(ip); i++ {
		switch ip[i] {
		case '.':
			// IPv4
			return ip
		case ':':
			// IPv6
			isIPv6 = true
		}
	}
	if !isIPv6 {
		// Not an IP address at all
		return ip
	}

	ipv6 := net.ParseIP(ip)
	if ipv6 == nil {
		return ip
	}

	return ipv6.Mask(net.CIDRMask(64, 128)).String()
}
