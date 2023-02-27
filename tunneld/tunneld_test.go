package tunneld_test

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cdr.dev/slog/sloggers/slogtest"
	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
)

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
		Log: slogtest.
			Make(t, &slogtest.Options{IgnoreErrors: true}).
			Named("tunnel_client"),
		PrivateKey: key,
	})
	require.NoError(t, err, "launch tunnel")
	defer func() {
		_ = tunnel.Close()
		<-tunnel.Wait()
	}()

	// Start a basic HTTP server with the listener.
	srv := &http.Server{
		// These errors are typically noise like "TLS: EOF". Vault does similar:
		// https://github.com/hashicorp/vault/blob/e2490059d0711635e529a4efcbaa1b26998d6e1c/command/server.go#L2714
		ErrorLog:          log.New(io.Discard, "", 0),
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("hello world " + r.URL.Path))
		}),
	}
	go func() {
		_ = srv.Serve(tunnel.Listener)
	}()
	defer func() {
		_ = srv.Close()
	}()

	// Because the DNS isn't setup we have to use a custom HTTP client that uses
	// the tunnel's dialer.
	c := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, client.URL.Host)
			},
		},
	}

	// Wait for the tunnel to be ready.
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tunnel.URL.String(), nil)
		require.NoError(t, err, "create request")

		res, err := c.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
		return err == nil && res.StatusCode == http.StatusOK
	}, 15*time.Second, 100*time.Millisecond)

	require.NotNil(t, tunnel.URL)
	require.Len(t, tunnel.OtherURLs, 1)
	require.NotEqual(t, tunnel.URL.String(), tunnel.OtherURLs[0].String())

	// Make a bunch of requests concurrently.
	var wg sync.WaitGroup
	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Do half of the requests to the primary URL and the other half to
			// the other URL (there's only one other URL right now).
			u := tunnel.URL
			if i%2 == 0 {
				u = tunnel.OtherURLs[0]
			}

			u, err := u.Parse("/test/" + strconv.Itoa(i))
			assert.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			assert.NoError(t, err)

			res, err := c.Do(req)
			if !assert.NoError(t, err) {
				return
			}
			defer res.Body.Close()
			assert.Equal(t, http.StatusOK, res.StatusCode)

			body, err := io.ReadAll(res.Body)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, "hello world /test/"+strconv.Itoa(i), string(body))
		}(i)
	}

	wg.Wait()

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
	if reflect.ValueOf(options.Log).IsZero() {
		options.Log = slogtest.
			Make(t, &slogtest.Options{IgnoreErrors: true}).
			Named("tunneld")
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
