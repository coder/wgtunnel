package tunneld_test

import (
	"fmt"
	"net/netip"
	"net/url"
	"testing"

	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_Option(t *testing.T) {
	t.Parallel()

	key, err := tunnelsdk.GeneratePrivateKey()
	require.NoError(t, err)

	t.Run("Validate", func(t *testing.T) {
		t.Parallel()

		t.Run("FullValid", func(t *testing.T) {
			t.Parallel()

			o := tunneld.Options{
				BaseURL: &url.URL{
					Scheme: "http",
					Host:   "localhost",
				},
				WireguardEndpoint:      "localhost:1234",
				WireguardPort:          1234,
				WireguardKey:           key,
				WireguardMTU:           tunneld.DefaultWireguardMTU + 1,
				WireguardServerIP:      netip.MustParseAddr("feed::1"),
				WireguardNetworkPrefix: netip.MustParsePrefix("feed::1/64"),
			}

			clone := o
			clone.BaseURL = &url.URL{
				Scheme: o.BaseURL.Scheme,
				Host:   o.BaseURL.Host,
			}
			clonePtr := &clone
			err := clonePtr.Validate()
			require.NoError(t, err)

			// Should not have updated the struct.
			require.Equal(t, o, clone)
		})

		t.Run("Valid", func(t *testing.T) {
			t.Parallel()

			o := &tunneld.Options{
				BaseURL: &url.URL{
					Scheme: "http",
					Host:   "localhost",
				},
				WireguardEndpoint: "localhost:1234",
				WireguardPort:     1234,
				WireguardKey:      key,
			}

			err := o.Validate()
			require.NoError(t, err)

			require.Equal(t, &url.URL{Scheme: "http", Host: "localhost"}, o.BaseURL)
			require.Equal(t, "localhost:1234", o.WireguardEndpoint)
			require.EqualValues(t, 1234, o.WireguardPort)
			require.Equal(t, key, o.WireguardKey)
			require.EqualValues(t, tunneld.DefaultWireguardMTU, o.WireguardMTU)
			require.Equal(t, tunneld.DefaultWireguardServerIP, o.WireguardServerIP)
			require.Equal(t, tunneld.DefaultWireguardNetworkPrefix, o.WireguardNetworkPrefix)
		})

		t.Run("Invalid", func(t *testing.T) {
			t.Parallel()

			t.Run("Nil", func(t *testing.T) {
				t.Parallel()

				err := (*tunneld.Options)(nil).Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "options is nil")
			})

			t.Run("BaseURL", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL:           nil,
					WireguardEndpoint: "localhost:1234",
					WireguardPort:     1234,
					WireguardKey:      key,
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "BaseURL is required")
			})

			t.Run("WireguardEndpoint", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost",
					},
					WireguardEndpoint: "",
					WireguardPort:     1234,
					WireguardKey:      key,
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardEndpoint is required")

				o.WireguardEndpoint = "localhost"

				err = o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "not a valid host:port")
			})

			t.Run("WireguardPort", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost",
					},
					WireguardEndpoint: "localhost:1234",
					WireguardPort:     0,
					WireguardKey:      key,
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardPort is required")
			})

			t.Run("WireguardKey", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost",
					},
					WireguardEndpoint: "localhost:1234",
					WireguardPort:     1234,
					WireguardKey:      tunnelsdk.Key{},
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardKey is required")

				o.WireguardKey, err = key.PublicKey()
				require.NoError(t, err)

				err = o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardKey must be a private key")
			})

			t.Run("WireguardServerIP", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost",
					},
					WireguardEndpoint: "localhost:1234",
					WireguardPort:     1234,
					WireguardKey:      key,
					WireguardServerIP: netip.MustParseAddr("127.0.0.1"),
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardServerIP must be an IPv6 address")
			})

			t.Run("WireguardNetworkPrefix", func(t *testing.T) {
				t.Parallel()

				o := &tunneld.Options{
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost",
					},
					WireguardEndpoint:      "localhost:1234",
					WireguardPort:          1234,
					WireguardKey:           key,
					WireguardServerIP:      netip.MustParseAddr("feed::1"),
					WireguardNetworkPrefix: netip.MustParsePrefix("feed::1/128"),
				}

				err := o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardNetworkPrefix must have at least 64 bits available")

				o.WireguardServerIP = netip.MustParseAddr("fcca::1")
				o.WireguardNetworkPrefix = netip.MustParsePrefix("feed::1/64")

				err = o.Validate()
				require.Error(t, err)
				require.ErrorContains(t, err, "WireguardServerIP must be contained within WireguardNetworkPrefix")
			})
		})
	})

	t.Run("WireguardPublicKeyToIP", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			// base64 encoded
			key string
			ip  string
		}{
			{
				key: "8HGwtvNSGqXyO2s7UCW/NtvQM7L5jUL+s76h3qZbeG0=",
				ip:  "f8bf:98cd:3caf:3e62",
			},
			{
				key: "ikEH8jCTwDMpQb7B1SbLi7itzDHJrlLzZtdNmuiLZHo=",
				ip:  "2150:c2ea:38fe:21f",
			},
			{
				key: "8yxYMm//sfv27tkSz9itIa/8Ihql+vFRpsvjTSTaYAg=",
				ip:  "c17e:72e4:c52e:a6c4",
			},
			{
				key: "Gl7xZzfkCyFTbB+Uejc17GmfbjLy6s8NEZBaJKx/swU=",
				ip:  "f773:2e08:771d:7a6f",
			},
			{
				key: "f8YjkcGgOggYzlIr2KtShY+8ZgR0hIXmJHPjCG8wi2Q=",
				ip:  "dcf1:4e76:15bd:b2c7",
			},
			{
				key: "Q3dubFlwwLnCpQTagjCckb1XLGtViZoBX1qHAZWV2gI=",
				ip:  "25a2:8a43:2e91:1543",
			},
		}

		for i, c := range cases {
			c := c

			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()

				pubKey, err := wgtypes.ParseKey(c.key)
				require.NoError(t, err)

				t.Run("Default", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "http",
							Host:   "localhost",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      tunneld.DefaultWireguardServerIP,
						WireguardNetworkPrefix: tunneld.DefaultWireguardNetworkPrefix,
					}
					err := options.Validate()
					require.NoError(t, err)

					expectedIP := "fcca::" + c.ip

					ip := options.WireguardPublicKeyToIP(device.NoisePublicKey(pubKey))
					require.Equal(t, expectedIP, ip.String())
				})

				t.Run("LongerPrefix", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "http",
							Host:   "localhost",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      netip.MustParseAddr("feed:beef:deaf:deed::1"),
						WireguardNetworkPrefix: netip.MustParsePrefix("feed:beef:deaf:deed::1/64"),
					}
					err := options.Validate()
					require.NoError(t, err)

					expectedIP := "feed:beef:deaf:deed:" + c.ip

					ip := options.WireguardPublicKeyToIP(device.NoisePublicKey(pubKey))
					require.Equal(t, expectedIP, ip.String())
				})
			})
		}
	})

	t.Run("WireguardIPToTunnelURL", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			ip  string
			url string
		}{
			{
				ip:  "f8bf:98cd:3caf:3e62",
				url: "http://v2vphj9slsv64.localhost.com",
			},
			{
				ip:  "2150:c2ea:38fe:21f",
				url: "http://458c5qhovo11u.localhost.com",
			},
			{
				ip:  "c17e:72e4:c52e:a6c4",
				url: "http://o5v75p655qjc8.localhost.com",
			},
			{
				ip:  "f773:2e08:771d:7a6f",
				url: "http://utpis23n3lt6u.localhost.com",
			},
			{
				ip:  "dcf1:4e76:15bd:b2c7",
				url: "http://rjokstglnmpce.localhost.com",
			},
			{
				ip:  "25a2:8a43:2e91:1543",
				url: "http://4mh8kgpei4ak6.localhost.com",
			},
		}

		for i, c := range cases {
			c := c

			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()

				t.Run("Default", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "http",
							Host:   "localhost.com",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      tunneld.DefaultWireguardServerIP,
						WireguardNetworkPrefix: tunneld.DefaultWireguardNetworkPrefix,
					}
					err := options.Validate()
					require.NoError(t, err)

					ip, err := netip.ParseAddr("fcca::" + c.ip)
					require.NoError(t, err)

					u := options.WireguardIPToTunnelURL(ip)
					require.Equal(t, c.url, u.String())
				})

				t.Run("LongerPrefix", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "https",
							Host:   "localhost.com",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      netip.MustParseAddr("feed:beef:deaf:deed::1"),
						WireguardNetworkPrefix: netip.MustParsePrefix("feed:beef:deaf:deed::1/64"),
					}
					err := options.Validate()
					require.NoError(t, err)

					ip, err := netip.ParseAddr("feed:beef:deaf:deed:" + c.ip)
					require.NoError(t, err)

					u := options.WireguardIPToTunnelURL(ip)
					require.Equal(t, "https", u.Scheme)
					u.Scheme = "http"
					require.Equal(t, c.url, u.String())
				})
			})
		}
	})

	t.Run("HostnameToWireguardIP", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			hostname    string
			ip          string
			errContains string
		}{
			{
				hostname: "v2vphj9slsv64",
				ip:       "f8bf:98cd:3caf:3e62",
			},
			{
				hostname: "458c5qhovo11u",
				ip:       "2150:c2ea:38fe:21f",
			},
			{
				hostname: "o5v75p655qjc8",
				ip:       "c17e:72e4:c52e:a6c4",
			},
			{
				hostname: "utpis23n3lt6u",
				ip:       "f773:2e08:771d:7a6f",
			},
			{
				hostname: "rjokstglnmpce",
				ip:       "dcf1:4e76:15bd:b2c7",
			},
			{
				hostname: "4mh8kgpei4ak6",
				ip:       "25a2:8a43:2e91:1543",
			},

			{
				hostname:    "v2vphj9slsv64.localhost.com",
				errContains: "failed to decode hostname",
			},
			{
				hostname:    "4mh8kgpei4ak64mh8kgpei4ak6",
				errContains: "invalid hostname length",
			},
		}

		for i, c := range cases {
			c := c

			t.Run(fmt.Sprint(i), func(t *testing.T) {
				t.Parallel()

				t.Run("Default", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "http",
							Host:   "localhost.com",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      tunneld.DefaultWireguardServerIP,
						WireguardNetworkPrefix: tunneld.DefaultWireguardNetworkPrefix,
					}
					err := options.Validate()
					require.NoError(t, err)

					ip, err := options.HostnameToWireguardIP(c.hostname)
					if c.errContains != "" {
						require.Error(t, err)
						require.ErrorContains(t, err, c.errContains)
						return
					}

					require.NoError(t, err)
					require.Equal(t, "fcca::"+c.ip, ip.String())
				})

				t.Run("LongerPrefix", func(t *testing.T) {
					t.Parallel()

					options := &tunneld.Options{
						BaseURL: &url.URL{
							Scheme: "http",
							Host:   "localhost.com",
						},
						WireguardEndpoint:      "localhost:1234",
						WireguardPort:          1234,
						WireguardKey:           key,
						WireguardServerIP:      netip.MustParseAddr("feed:beef:deaf:deed::1"),
						WireguardNetworkPrefix: netip.MustParsePrefix("feed:beef:deaf:deed::1/64"),
					}
					err := options.Validate()
					require.NoError(t, err)

					ip, err := options.HostnameToWireguardIP(c.hostname)
					if c.errContains != "" {
						require.Error(t, err)
						require.ErrorContains(t, err, c.errContains)
						return
					}

					require.NoError(t, err)
					require.Equal(t, "feed:beef:deaf:deed:"+c.ip, ip.String())
				})
			})
		}
	})
}
