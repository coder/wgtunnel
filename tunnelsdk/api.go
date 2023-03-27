package tunnelsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

type Response struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

type ClientRegisterRequest struct {
	Version   TunnelVersion         `json:"version"`
	PublicKey device.NoisePublicKey `json:"public_key"`
}

type ClientRegisterResponse struct {
	Version   TunnelVersion `json:"version"`
	PollEvery time.Duration `json:"poll_every"`
	// TunnelURLs contains a list of valid URLs that will be forwarded from the
	// server to this tunnel client once connected. The first URL is the
	// preferred URL, and the other URLs are provided for compatibility
	// purposes only.
	//
	// The order of the URLs changes based on the Version field in the request.
	TunnelURLs []string   `json:"tunnel_urls"`
	ClientIP   netip.Addr `json:"client_ip"`

	ServerEndpoint  string                `json:"server_endpoint"`
	ServerIP        netip.Addr            `json:"server_ip"`
	ServerPublicKey device.NoisePublicKey `json:"server_public_key"`
	WireguardMTU    int                   `json:"wireguard_mtu"`
}

func (c *Client) ClientRegister(ctx context.Context, req ClientRegisterRequest) (ClientRegisterResponse, error) {
	res, err := c.Request(ctx, http.MethodPost, "/api/v2/clients", req)
	if err != nil {
		return ClientRegisterResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ClientRegisterResponse{}, readBodyAsError(res)
	}

	var resp ClientRegisterResponse
	return resp, json.NewDecoder(res.Body).Decode(&resp)
}
