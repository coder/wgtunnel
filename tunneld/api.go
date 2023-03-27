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

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/hostrouter"
	"github.com/riandyrn/otelchi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/xerrors"
	"golang.zx2c4.com/wireguard/device"

	"github.com/coder/wgtunnel/tunneld/httpapi"
	"github.com/coder/wgtunnel/tunneld/httpmw"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func (api *API) Router() http.Handler {
	var (
		hr            = hostrouter.New()
		apiRouter     = chi.NewRouter()
		proxyRouter   = chi.NewRouter()
		unknownRouter = chi.NewRouter()
	)

	hr.Map(api.BaseURL.Host, apiRouter)
	hr.Map("*."+api.BaseURL.Host, proxyRouter)
	hr.Map("*", unknownRouter)

	proxyRouter.Use(
		otelchi.Middleware("proxy"),
		httpmw.LimitBody(50*1<<20), // 50MB
	)
	proxyRouter.Mount("/", http.HandlerFunc(api.handleTunnel))

	apiRouter.Use(
		otelchi.Middleware("api", otelchi.WithChiRoutes(apiRouter)),
		httpmw.LimitBody(1<<20), // 1MB
		httpmw.RateLimit(httpmw.RateLimitConfig{
			Log:          api.Log.Named("ratelimier"),
			Count:        10,
			Window:       10 * time.Second,
			RealIPHeader: api.Options.RealIPHeader,
		}),
	)

	apiRouter.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https://coder.com"))
	})
	apiRouter.Post("/tun", api.postTun)
	apiRouter.Post("/api/v2/clients", api.postClients)

	notFound := func(rw http.ResponseWriter, r *http.Request) {
		httpapi.Write(r.Context(), rw, http.StatusNotFound, tunnelsdk.Response{
			Message: "Not found.",
		})
	}
	apiRouter.NotFound(notFound)
	unknownRouter.NotFound(notFound)

	return hr
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

	api.pkeyCacheMu.Lock()
	api.pkeyCache[ip] = cachedPeer{
		key:           req.PublicKey,
		lastHandshake: time.Now(),
	}
	api.pkeyCacheMu.Unlock()

	exists := true
	if api.wgDevice.LookupPeer(req.PublicKey) == nil {
		exists = false

		api.pkeyCacheMu.Lock()
		api.pkeyCache[ip] = struct {
			key           device.NoisePublicKey
			lastHandshake time.Time
		}{
			key:           req.PublicKey,
			lastHandshake: time.Now(),
		}
		api.pkeyCacheMu.Unlock()

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
		PollEvery:       api.PeerPollDuration,
		TunnelURLs:      urlsStr,
		ClientIP:        ip,
		ServerEndpoint:  api.WireguardEndpoint,
		ServerIP:        api.WireguardServerIP,
		ServerPublicKey: api.WireguardKey.NoisePublicKey(),
		WireguardMTU:    api.WireguardMTU,
	}, exists, nil
}

type ipPortKey struct{}

func peerNotConnected(ctx context.Context, rw http.ResponseWriter, r *http.Request) {
	httpapi.Write(ctx, rw, http.StatusBadGateway, tunnelsdk.Response{
		Message: "Peer is not connected.",
		Detail:  "",
	})
}

func (api *API) handleTunnel(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	host := r.Host
	subdomain, _ := splitHostname(host)
	subdomainParts := strings.Split(subdomain, "-")
	user := subdomainParts[len(subdomainParts)-1]

	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Bool("proxy_request", true),
		attribute.String("user", user),
	)

	ip, err := api.HostnameToWireguardIP(user)
	if err != nil {
		httpapi.Write(ctx, rw, http.StatusBadRequest, tunnelsdk.Response{
			Message: "Invalid tunnel URL.",
			Detail:  err.Error(),
		})
		return
	}

	api.pkeyCacheMu.RLock()
	pkey, ok := api.pkeyCache[ip]
	api.pkeyCacheMu.RUnlock()

	if !ok || time.Since(pkey.lastHandshake) > api.PeerTimeout {
		peerNotConnected(ctx, rw, r)
		return
	}

	peer := api.wgDevice.LookupPeer(pkey.key)
	if peer == nil {
		peerNotConnected(ctx, rw, r)
		return
	}

	// The transport on the reverse proxy uses this ctx value to know which
	// IP to dial. See tunneld.go.
	ctx = context.WithValue(ctx, ipPortKey{}, netip.AddrPortFrom(ip, tunnelsdk.TunnelPort))
	r = r.WithContext(ctx)

	rp := httputil.ReverseProxy{
		// This can only happen when it fails to dial.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			httpapi.Write(ctx, rw, http.StatusBadGateway, tunnelsdk.Response{
				Message: "Failed to dial peer.",
				Detail:  err.Error(),
			})
		},
		Director: func(rp *http.Request) {
			rp.URL.Scheme = "http"
			rp.URL.Host = r.Host
			rp.Host = r.Host
		},
		Transport: api.transport,
	}

	rp.ServeHTTP(rw, r)
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
