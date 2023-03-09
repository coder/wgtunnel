package tunneld

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/xerrors"
	"golang.zx2c4.com/wireguard/device"

	"github.com/coder/wgtunnel/tunneld/httpapi"
	"github.com/coder/wgtunnel/tunneld/httpmw"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func (api *API) Router() chi.Router {
	r := chi.NewRouter()

	r.Use(
		httpmw.LimitBody(50*1<<20), // 50MB
		api.handleTunnelMW,

		// Post tunnel middleware, this middleware will never execute on
		// tunneled connections.
		httpmw.LimitBody(1<<20), // change back to 1MB
		httpmw.RateLimit(10, 10*time.Second),
	)

	r.Post("/tun", api.postTun)
	r.Post("/api/v2/clients", api.postClients)

	r.NotFound(func(rw http.ResponseWriter, r *http.Request) {
		httpapi.Write(r.Context(), rw, http.StatusNotFound, tunnelsdk.Response{
			Message: "Not found.",
		})
	})

	return r
}

type LegacyPostTunRequest struct {
	PublicKey device.NoisePublicKey `json:"public_key"`
}

type LegacyPostTunResponse struct {
	Hostname        string     `json:"hostname"`
	ServerEndpoint  string     `json:"server_endpoint"`
	ServerIP        netip.Addr `json:"server_ip"`
	ServerPublicKey string     `json:"server_public_key"` // hex
	ClientIP        netip.Addr `json:"client_ip"`
}

// postTun provides compatibility with the old tunnel client contained in older
// versions of coder/coder. It essentially converts the old request format to a
// newer request, and the newer response to the old response format.
func (api *API) postTun(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req LegacyPostTunRequest
	if !httpapi.Read(ctx, rw, r, &req) {
		return
	}

	registerReq := tunnelsdk.ClientRegisterRequest{
		Version:   tunnelsdk.TunnelVersion1,
		PublicKey: req.PublicKey,
	}

	resp, exists, err := api.registerClient(registerReq)
	if err != nil {
		httpapi.Write(ctx, rw, http.StatusInternalServerError, tunnelsdk.Response{
			Message: "Failed to register client.",
			Detail:  err.Error(),
		})
		return
	}

	if len(resp.TunnelURLs) == 0 {
		httpapi.Write(ctx, rw, http.StatusInternalServerError, tunnelsdk.Response{
			Message: "No tunnel URLs found.",
		})
		return
	}

	u, err := url.Parse(resp.TunnelURLs[0])
	if err != nil {
		httpapi.Write(ctx, rw, http.StatusInternalServerError, tunnelsdk.Response{
			Message: "Failed to parse tunnel URL.",
			Detail:  err.Error(),
		})
		return
	}

	status := http.StatusCreated
	if exists {
		status = http.StatusOK
	}
	httpapi.Write(ctx, rw, status, LegacyPostTunResponse{
		Hostname:        u.Host,
		ServerEndpoint:  resp.ServerEndpoint,
		ServerIP:        resp.ServerIP,
		ServerPublicKey: hex.EncodeToString(resp.ServerPublicKey[:]),
		ClientIP:        resp.ClientIP,
	})
}

func (api *API) postClients(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req tunnelsdk.ClientRegisterRequest
	if !httpapi.Read(r.Context(), rw, r, &req) {
		return
	}

	resp, _, err := api.registerClient(req)
	if err != nil {
		httpapi.Write(ctx, rw, http.StatusInternalServerError, tunnelsdk.Response{
			Message: "Failed to register client.",
			Detail:  err.Error(),
		})
		return
	}

	httpapi.Write(ctx, rw, http.StatusOK, resp)
}

func (api *API) registerClient(req tunnelsdk.ClientRegisterRequest) (tunnelsdk.ClientRegisterResponse, bool, error) {
	if req.Version <= 0 || req.Version > tunnelsdk.TunnelVersionLatest {
		req.Version = tunnelsdk.TunnelVersionLatest
	}

	ip, urls := api.WireguardPublicKeyToIPAndURLs(req.PublicKey, req.Version)

	exists := true
	if api.wgDevice.LookupPeer(req.PublicKey) == nil {
		exists = false

		err := api.wgDevice.IpcSet(fmt.Sprintf(`public_key=%x
allowed_ip=%s/128`,
			req.PublicKey,
			ip.String(),
		))
		if err != nil {
			return tunnelsdk.ClientRegisterResponse{}, false, xerrors.Errorf("register client with wireguard: %w", err)
		}
	}

	urlsStr := make([]string, len(urls))
	for i, u := range urls {
		urlsStr[i] = u.String()
	}

	return tunnelsdk.ClientRegisterResponse{
		Version:         req.Version,
		TunnelURLs:      urlsStr,
		ClientIP:        ip,
		ServerEndpoint:  api.WireguardEndpoint,
		ServerIP:        api.WireguardServerIP,
		ServerPublicKey: api.WireguardKey.NoisePublicKey(),
		WireguardMTU:    api.WireguardMTU,
	}, exists, nil
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

		dialCtx, dialCancel := context.WithTimeout(ctx, api.Options.PeerDialTimeout)
		defer dialCancel()

		nc, err := api.wgNet.DialContextTCPAddrPort(dialCtx, netip.AddrPortFrom(ip, tunnelsdk.TunnelPort))
		if err != nil {
			httpapi.Write(ctx, rw, http.StatusBadGateway, tunnelsdk.Response{
				Message: "Failed to dial peer.",
				Detail:  err.Error(),
			})
			return
		}

		span := trace.SpanFromContext(ctx)
		span.SetAttributes(attribute.Bool("proxy_request", true))

		rp := httputil.ReverseProxy{
			Director: func(rp *http.Request) {
				rp.URL.Scheme = "http"
				rp.URL.Host = r.Host
				rp.Host = r.Host
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return &tracingConnWrapper{
						Conn: nc,
						span: span,
						ctx:  ctx,
					}, nil
				},
			},
		}

		span.End()
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
