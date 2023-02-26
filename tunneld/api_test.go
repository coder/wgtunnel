package tunneld_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coder/wgtunnel/tunnelsdk"
)

func Test_postClients(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, nil)

	key, err := tunnelsdk.GeneratePrivateKey()
	require.NoError(t, err)

	expectedIP, expectedURLs := td.WireguardPublicKeyToIPAndURLs(key.NoisePublicKey())

	expectedURLsStr := make([]string, len(expectedURLs))
	for i, u := range expectedURLs {
		expectedURLsStr[i] = u.String()
	}

	// Register a client.
	res, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)

	require.Equal(t, expectedURLsStr, res.TunnelURLs)
	require.Equal(t, expectedIP, res.ClientIP)
	require.Equal(t, td.WireguardEndpoint, res.ServerEndpoint)
	require.Equal(t, td.WireguardServerIP, res.ServerIP)
	require.Equal(t, td.WireguardKey.NoisePublicKey(), res.ServerPublicKey)
	require.Equal(t, td.WireguardMTU, res.WireguardMTU)

	// Register the same client again.
	res2, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
		PublicKey: key.NoisePublicKey(),
	})
	require.NoError(t, err)
	require.Equal(t, res, res2)
}
