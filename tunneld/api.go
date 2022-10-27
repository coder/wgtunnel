package tunneld

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi"

	"github.com/coder/wgtunnel/tunneld/httpapi"
	"github.com/coder/wgtunnel/tunneld/httpmw"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func (api *API) Router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		httpmw.LimitBody(1<<20), // 1MB
		httpmw.RateLimit(10, 10*time.Second),
		api.handleTunnelMW,
	)

	r.Post("/api/v1/clients", api.postClients)

	r.NotFound(func(rw http.ResponseWriter, r *http.Request) {
		httpapi.Write(r.Context(), rw, http.StatusNotFound, tunnelsdk.Response{
			Message: "Not found.",
		})
	})

	return r
}

func (api *API) postClients(rw http.ResponseWriter, r *http.Request) {
	var req tunnelsdk.ClientRegisterRequest
	if !httpapi.Read(r.Context(), rw, r, &req) {
		return
	}

	ip := api.WireguardPublicKeyToIP(req.PublicKey)
	if api.wgDevice.LookupPeer(req.PublicKey) == nil {
		err := api.wgDevice.IpcSet(fmt.Sprintf("public_key=%x\nallowed_ip=%s/128", req.PublicKey, ip.String()))
		if err != nil {
			httpapi.Write(r.Context(), rw, http.StatusInternalServerError, tunnelsdk.Response{
				Message: "Failed to register client.",
				Detail:  err.Error(),
			})
			return
		}
	}

	httpapi.Write(r.Context(), rw, http.StatusOK, tunnelsdk.ClientRegisterResponse{
		TunnelURL:       api.WireguardIPToTunnelURL(ip).String(),
		ClientIP:        ip,
		ServerEndpoint:  api.WireguardEndpoint,
		ServerIP:        api.WireguardServerIP,
		ServerPublicKey: api.WireguardKey.NoisePublicKey(),
		WireguardMTU:    api.WireguardMTU,
	})
}

func (api *API) handleTunnelMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if the request looks like a tunnel request.
		host := r.Host
		if host == "" {
			httpapi.Write(ctx, rw, http.StatusBadRequest, tunnelsdk.Response{
				Message: "Missing Host header.",
			})
			return
		}

		subdomain, rest := splitHostname(host)
		if rest != api.BaseURL.Hostname() {
			// Doesn't look like a tunnel request.
			next.ServeHTTP(rw, r)
			return
		}

		subdomainParts := strings.Split(subdomain, "-")
		ip, err := api.HostnameToWireguardIP(subdomainParts[len(subdomainParts)-1])
		if err != nil {
			httpapi.Write(ctx, rw, http.StatusBadRequest, tunnelsdk.Response{
				Message: "Invalid tunnel URL.",
				Detail:  err.Error(),
			})
			return
		}

		rp := httputil.ReverseProxy{
			Director: func(rp *http.Request) {
				rp.URL.Scheme = "http"
				rp.URL.Host = r.Host
				rp.Host = r.Host
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					nc, err := api.wgNet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(ip, tunnelsdk.TunnelPort))
					if err != nil {
						return nil, err
					}

					/*
						TODO: add tracing back
						if traceNetconn {
							return &netconnWrapper{
								Conn: nc,
								span: span,
								ctx:  ctx,
							}, nil
						}
					*/

					return nc, nil
				},
			},
		}

		rp.ServeHTTP(rw, r)
	})
}

// splitHostname splits a hostname into the subdomain and the rest of the
// string, stripping any port data and leading/trailing periods.
func splitHostname(hostname string) (subdomain string, rest string) {
	hostname = strings.Trim(hostname, ".")
	hostnameHost, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = hostnameHost
	}

	parts := strings.SplitN(hostname, ".", 2)
	if len(parts) != 2 {
		return hostname, ""
	}

	return parts[0], parts[1]
}
