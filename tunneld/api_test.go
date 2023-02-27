package tunneld_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
)

// Test for the compatibility endpoint which allows old tunnels to connect to
// the new server.
func Test_postTun(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, nil)

	key, err := tunnelsdk.GeneratePrivateKey()
	require.NoError(t, err)

	expectedIP, expectedURLs := td.WireguardPublicKeyToIPAndURLs(key.NoisePublicKey(), tunnelsdk.TunnelVersion1)
	require.Len(t, expectedURLs, 2)
	require.Len(t, strings.Split(expectedURLs[0].Host, ".")[0], 32)
	expectedHostname := expectedURLs[0].Host

	resp, err := client.Request(context.Background(), http.MethodPost, "/tun", tunneld.LegacyPostTunRequest{
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var legacyRes tunneld.LegacyPostTunResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&legacyRes))
	require.Equal(t, expectedIP, legacyRes.ClientIP)
	require.Equal(t, expectedHostname, legacyRes.Hostname)

	// Register on the new endpoint so we can compare the values to the legacy
	// endpoint.
	newRes, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		Version:   tunnelsdk.TunnelVersion1,
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)
	require.Equal(t, tunnelsdk.TunnelVersion1, newRes.Version)

	require.Equal(t, legacyRes.ServerEndpoint, newRes.ServerEndpoint)
	require.Equal(t, legacyRes.ServerIP, newRes.ServerIP)
	require.Equal(t, legacyRes.ServerPublicKey, hex.EncodeToString(newRes.ServerPublicKey[:]))
	require.Equal(t, legacyRes.ClientIP, newRes.ClientIP)
}

func Test_postClients(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, nil)

	key, err := tunnelsdk.GeneratePrivateKey()
	require.NoError(t, err)

	expectedIP, expectedURLs := td.WireguardPublicKeyToIPAndURLs(key.NoisePublicKey(), tunnelsdk.TunnelVersion2)

	expectedURLsStr := make([]string, len(expectedURLs))
	for i, u := range expectedURLs {
		expectedURLsStr[i] = u.String()
	}

	// Register a client.
	res, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		// No version should default to 2.
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)

	require.Equal(t, tunnelsdk.TunnelVersion2, res.Version)
	require.Equal(t, expectedURLsStr, res.TunnelURLs)
	require.Equal(t, expectedIP, res.ClientIP)
	require.Equal(t, td.WireguardEndpoint, res.ServerEndpoint)
	require.Equal(t, td.WireguardServerIP, res.ServerIP)
	require.Equal(t, td.WireguardKey.NoisePublicKey(), res.ServerPublicKey)
	require.Equal(t, td.WireguardMTU, res.WireguardMTU)

	// Register the same client again.
	res2, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		Version:   tunnelsdk.TunnelVersion2,
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)
	require.Equal(t, res, res2)

	// Register the same client with the old version.
	res3, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		Version:   tunnelsdk.TunnelVersion1,
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)

	// Should be equal after reversing the URL list.
	require.Equal(t, tunnelsdk.TunnelVersion1, res3.Version)
	res3.TunnelURLs[0], res3.TunnelURLs[1] = res3.TunnelURLs[1], res3.TunnelURLs[0]
	res3.Version = tunnelsdk.TunnelVersion2
	require.Equal(t, res, res3)
}
