package tunneld_test

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

	require.NotNil(t, tunnel.URL)
	require.Len(t, tunnel.OtherURLs, 1)
	require.NotEqual(t, tunnel.URL.String(), tunnel.OtherURLs[0].String())

	serveTunnel(t, tunnel)
	c := tunnelHTTPClient(client)
	waitForTunnelReady(t, c, tunnel)

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

			// Do a third of the requests with a prefix before the hostname.
			if i%3 == 0 {
				u.Host = "prefix--" + u.Host
			}

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

// This test ensures that wgtunnel is compatible with the old closed-source
// wgtunnel when register requests are made with version 1.
//
// This uses real values generated by the old wgtunnel source code and checks
// that the new wgtunnel can parse them and generates the expected values.
func TestCompatibility(t *testing.T) {
	t.Parallel()

	/*
		wgKey: mCW7PwpK8iBmyXEFyGk55G24H0IU/AmJf5ZerzA3jGY=
		wgPubKey: Y9psPgU9BNRCvjPR93RNghbJUPyVh0LXBTnbHb+0TgU=
		publicKeyToV6: fcca:bbaf:8a9b:77f9:3fa9:fa65:7677:155e
		v6ToString: fccabbaf8a9b77f93fa9fa657677155e
		stringToV6: fcca:bbaf:8a9b:77f9:3fa9:fa65:7677:155e
	*/

	clientKey, err := tunnelsdk.ParsePrivateKey("mCW7PwpK8iBmyXEFyGk55G24H0IU/AmJf5ZerzA3jGY=")
	require.NoError(t, err)
	require.Equal(t, "mCW7PwpK8iBmyXEFyGk55G24H0IU/AmJf5ZerzA3jGY=", clientKey.String())

	clientPublicKey, err := clientKey.PublicKey()
	require.NoError(t, err)
	require.Equal(t, "Y9psPgU9BNRCvjPR93RNghbJUPyVh0LXBTnbHb+0TgU=", clientPublicKey.String())

	t.Run("Default", func(t *testing.T) {
		t.Parallel()

		td, client := createTestTunneld(t, &tunneld.Options{
			BaseURL: &url.URL{
				Scheme: "http",
				Host:   "localhost.com",
			},
			WireguardEndpoint:      "",              // generated automatically
			WireguardPort:          0,               // generated automatically
			WireguardKey:           tunnelsdk.Key{}, // generated automatically
			WireguardServerIP:      tunneld.DefaultWireguardServerIP,
			WireguardNetworkPrefix: tunneld.DefaultWireguardNetworkPrefix,
		})
		require.NotNil(t, td)

		ip1, urls1 := td.Options.WireguardPublicKeyToIPAndURLs(clientPublicKey.NoisePublicKey(), tunnelsdk.TunnelVersion1)
		ip2, urls2 := td.Options.WireguardPublicKeyToIPAndURLs(clientPublicKey.NoisePublicKey(), tunnelsdk.TunnelVersion2)

		// Identical IP address in both formats. This differs from the old
		// wgtunnel which uses all 16 bytes of the IP instead of just the prefix
		// and 8 bytes of the public key, but old clients don't care about the
		// IP anyways.
		require.Equal(t, ip1, ip2)
		// Swapped order of URLs in the new format.
		require.Equal(t, []string{urls1[0].String(), urls1[1].String()}, []string{urls2[1].String(), urls2[0].String()})
		require.Equal(t, "fccabbaf8a9b77f93fa9fa657677155e.localhost.com", urls1[0].Host)

		// Register with the old format.
		res, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
			Version:   tunnelsdk.TunnelVersion1,
			PublicKey: clientPublicKey.NoisePublicKey(),
		})
		require.NoError(t, err)

		require.Equal(t, tunnelsdk.TunnelVersion1, res.Version)
		require.Equal(t, "http://fccabbaf8a9b77f93fa9fa657677155e.localhost.com", res.TunnelURLs[0])
		require.Equal(t, ip1, res.ClientIP)

		// Now actually tunnel and check that the URL works.
		tunnel, err := client.LaunchTunnel(context.Background(), tunnelsdk.TunnelConfig{
			Log: slogtest.Make(t, &slogtest.Options{
				IgnoreErrors: true,
			}),
			Version:    tunnelsdk.TunnelVersion1,
			PrivateKey: clientKey,
		})
		require.NoError(t, err)
		require.NotNil(t, tunnel)

		serveTunnel(t, tunnel)
		c := tunnelHTTPClient(client)
		waitForTunnelReady(t, c, tunnel)

		// Make a request to the tunnel.
		{
			u, err := url.Parse(res.TunnelURLs[0])
			require.NoError(t, err)
			u.Path = "/test/1"

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
			assert.Equal(t, "hello world /test/1", string(body))
		}
	})

	// This test is mostly for completeness, but we don't use the longer prefix
	// functionality anyways, and it's not compatible with the old wgtunnel
	// implementation.
	t.Run("LongerPrefix", func(t *testing.T) {
		t.Parallel()

		td, client := createTestTunneld(t, &tunneld.Options{
			BaseURL: &url.URL{
				Scheme: "http",
				Host:   "localhost.com",
			},
			WireguardEndpoint:      "",              // generated automatically
			WireguardPort:          0,               // generated automatically
			WireguardKey:           tunnelsdk.Key{}, // generated automatically
			WireguardServerIP:      netip.MustParseAddr("feed:beef:deaf:deed::1"),
			WireguardNetworkPrefix: netip.MustParsePrefix("feed:beef:deaf:deed::1/64"),
		})
		require.NotNil(t, td)

		ip1, urls1 := td.Options.WireguardPublicKeyToIPAndURLs(clientPublicKey.NoisePublicKey(), tunnelsdk.TunnelVersion1)
		ip2, urls2 := td.Options.WireguardPublicKeyToIPAndURLs(clientPublicKey.NoisePublicKey(), tunnelsdk.TunnelVersion2)

		// Identical IP address in both formats. This differs from the old
		// wgtunnel which uses all 16 bytes of the IP instead of just the prefix
		// and 8 bytes of the public key, but old clients don't care about the
		// IP anyways.
		require.Equal(t, ip1, ip2)
		// Swapped order of URLs in the new format.
		require.Equal(t, []string{urls1[0].String(), urls1[1].String()}, []string{urls2[1].String(), urls2[0].String()})

		// For longer prefix, we use the prefix bytes, then the public key
		// bytes. We don't do any shifting.
		require.Equal(t, "feedbeefdeafdeedbbaf8a9b77f93fa9.localhost.com", urls1[0].Host)

		// Register with the old format.
		res, err := client.ClientRegister(context.Background(), tunnelsdk.ClientRegisterRequest{
			Version:   tunnelsdk.TunnelVersion1,
			PublicKey: clientPublicKey.NoisePublicKey(),
		})
		require.NoError(t, err)

		require.Equal(t, tunnelsdk.TunnelVersion1, res.Version)
		require.Equal(t, "http://feedbeefdeafdeedbbaf8a9b77f93fa9.localhost.com", res.TunnelURLs[0])
		require.Equal(t, ip1, res.ClientIP)

		// Now actually tunnel and check that the URL works.
		tunnel, err := client.LaunchTunnel(context.Background(), tunnelsdk.TunnelConfig{
			Log: slogtest.Make(t, &slogtest.Options{
				IgnoreErrors: true,
			}),
			Version:    tunnelsdk.TunnelVersion1,
			PrivateKey: clientKey,
		})
		require.NoError(t, err)
		require.NotNil(t, tunnel)

		serveTunnel(t, tunnel)
		c := tunnelHTTPClient(client)
		waitForTunnelReady(t, c, tunnel)

		// Make a request to the tunnel.
		{
			u, err := url.Parse(res.TunnelURLs[0])
			require.NoError(t, err)
			u.Path = "/test/1"

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
			assert.Equal(t, "hello world /test/1", string(body))
		}
	})
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	td, client := createTestTunneld(t, &tunneld.Options{
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "localhost.com",
		},
		WireguardEndpoint:      "",              // generated automatically
		WireguardPort:          0,               // generated automatically
		WireguardKey:           tunnelsdk.Key{}, // generated automatically
		WireguardServerIP:      tunneld.DefaultWireguardServerIP,
		WireguardNetworkPrefix: tunneld.DefaultWireguardNetworkPrefix,
		PeerDialTimeout:        time.Second,
	})
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

	// Close the tunnel.
	err = tunnel.Close()
	require.NoError(t, err, "close tunnel")
	<-tunnel.Wait()

	// Requests should fail in roughly 1 second.
	c := tunnelHTTPClient(client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := *tunnel.URL
	u.Path = "/test/1"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	now := time.Now()
	res, err := c.Do(req)
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(time.Second), time.Now(), 2*time.Second)
	defer res.Body.Close()
	require.Equal(t, http.StatusBadGateway, res.StatusCode)
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

func serveTunnel(t *testing.T, tunnel *tunnelsdk.Tunnel) {
	t.Helper()

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

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(tunnel.Listener)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
}

// tunnelHTTPClient returns a HTTP client that disregards DNS and always
// connects to the tunneld server IP. This is useful for testing connections to
// generated tunnel URLs with custom hostnames that don't resolve.
func tunnelHTTPClient(client *tunnelsdk.Client) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, client.URL.Host)
			},
		},
	}
}

func waitForTunnelReady(t *testing.T, c *http.Client, tunnel *tunnelsdk.Tunnel) {
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
}
