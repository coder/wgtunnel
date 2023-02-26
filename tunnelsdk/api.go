package tunnelsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"

	"golang.zx2c4.com/wireguard/device"
)

type Response struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

type ClientRegisterRequest struct {
	PublicKey device.NoisePublicKey `json:"public_key"`
}

type ClientRegisterResponse struct {
	TunnelURL string     `json:"tunnel_url"`
	ClientIP  netip.Addr `json:"client_ip"`

	ServerEndpoint  string                `json:"server_endpoint"`
	ServerIP        netip.Addr            `json:"server_ip"`
	ServerPublicKey device.NoisePublicKey `json:"server_public_key"`
	WireguardMTU    int                   `json:"wireguard_mtu"`
}

func (c *Client) ClientRegister(ctx context.Context, req ClientRegisterRequest) (ClientRegisterResponse, error) {
	res, err := c.request(ctx, http.MethodPost, "/api/v1/clients", req)
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
