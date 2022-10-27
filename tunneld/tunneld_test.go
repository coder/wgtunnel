package tunneld_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"cdr.dev/slog/sloggers/slogtest"
	"github.com/stretchr/testify/require"

	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func TestNew(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, nil)
	require.NotNil(t, td)
	require.NotNil(t, client)

	res, err := client.Request(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	_ = res.Body.Close()
	require.Equal(t, http.StatusNotFound, res.StatusCode)
}

// TestEndToEnd does an end-to-end tunnel test by creating a tunneld server, a
// client, setting up the tunnel, and then doing a bunch of tests through the
// tunnel to ensure it works.
func TestEndToEnd(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, nil)
	require.NotNil(t, td)

	// Start a tunnel.
	key, err := tunnelsdk.GeneratePrivateKey()
	require.NoError(t, err, "generate private key")
	tunnel, err := client.LaunchTunnel(context.Background(), tunnelsdk.TunnelConfig{
		Log:        slogtest.Make(t, &slogtest.Options{IgnoreErrors: true}),
		PrivateKey: key,
	})
	require.NoError(t, err, "launch tunnel")
	t.Cleanup(func() {
		_ = tunnel.Close()
		<-tunnel.Wait()
	})

	// Start a basic HTTP server with the listener.
	srv := &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("hello world " + r.URL.Path))
		}),
	}
	go func() {
		_ = srv.Serve(tunnel.Listener)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})

	// Make a bunch of requests through the tunnel. Because the DNS isn't setup
	// we have to use a custom HTTP client that uses the tunnel's dialer.
	c := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, client.URL.Host)
			},
		},
	}
	for i := 0; i < 1024; i++ {
		u, err := tunnel.URL.Parse("/test/" + strconv.Itoa(i))
		require.NoError(t, err)

		res, err := c.Get(u.String())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, "hello world /test/"+strconv.Itoa(i), string(body))
	}

	err = tunnel.Close()
	require.NoError(t, err, "close tunnel")

	<-tunnel.Wait()
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()

	l, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	require.NoError(t, err, "listen on random UDP port")

	_, port, err := net.SplitHostPort(l.LocalAddr().String())
	require.NoError(t, err, "split host port")

	portUint, err := strconv.ParseUint(port, 10, 16)
	require.NoError(t, err, "parse port")

	// This is prone to races, but since we have to tell wireguard to create the
	// listener and can't pass in a net.Listener, we have to do this.
	err = l.Close()
	require.NoError(t, err, "close UDP listener")

	return uint16(portUint)
}

func createTestTunneld(t *testing.T, options *tunneld.Options) (*tunneld.API, *tunnelsdk.Client) {
	t.Helper()

	if options == nil {
		options = &tunneld.Options{}
	}

	// Set required options if unset.
	if options.BaseURL == nil {
		options.BaseURL = &url.URL{
			Scheme: "http",
			Host:   "tunnel.dev",
		}
	}
	if options.WireguardEndpoint == "" && options.WireguardPort == 0 {
		port := freeUDPPort(t)
		options.WireguardEndpoint = "127.0.0.1:" + strconv.Itoa(int(port))
		options.WireguardPort = port
	}
	if options.WireguardKey.IsZero() {
		key, err := tunnelsdk.GeneratePrivateKey()
		require.NoError(t, err, "generate wireguard private key")
		options.WireguardKey = key
	}

	err := options.Validate()
	require.NoError(t, err, "validate options")

	return createTestTunneldNoDefaults(t, options)
}

func createTestTunneldNoDefaults(t *testing.T, options *tunneld.Options) (*tunneld.API, *tunnelsdk.Client) {
	t.Helper()

	td, err := tunneld.New(options)
	require.NoError(t, err, "create tunneld")
	t.Cleanup(func() {
		_ = td.Close()
	})

	srv := httptest.NewServer(td.Router())
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err, "parse server URL")

	client := tunnelsdk.New(u)
	return td, client
}
