package tunneld_test

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
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

	t.Run("WireguardPublicKeyToIPAndURLs", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			// base64 encoded
			key  string
			ip   string
			urls []string
		}{
			{
				key: "8HGwtvNSGqXyO2s7UCW/NtvQM7L5jUL+s76h3qZbeG0=",
				ip:  "f8bf:98cd:3caf:3e62",
				urls: []string{
					"http://v2vphj9slsv64.localhost.com",
					"http://fccaf8bf98cd3caf3e6270a5db3140f9.localhost.com",
				},
			},
			{
				key: "ikEH8jCTwDMpQb7B1SbLi7itzDHJrlLzZtdNmuiLZHo=",
				ip:  "2150:c2ea:38fe:21f",
				urls: []string{
					"http://458c5qhovo11u.localhost.com",
					"http://fcca2150c2ea38fe021f76fac00cd533.localhost.com",
				},
			},
			{
				key: "8yxYMm//sfv27tkSz9itIa/8Ihql+vFRpsvjTSTaYAg=",
				ip:  "c17e:72e4:c52e:a6c4",
				urls: []string{
					"http://o5v75p655qjc8.localhost.com",
					"http://fccac17e72e4c52ea6c4fbb4ef809339.localhost.com",
				},
			},
			{
				key: "Gl7xZzfkCyFTbB+Uejc17GmfbjLy6s8NEZBaJKx/swU=",
				ip:  "f773:2e08:771d:7a6f",
				urls: []string{
					"http://utpis23n3lt6u.localhost.com",
					"http://fccaf7732e08771d7a6f6fdcb4a1f367.localhost.com",
				},
			},
			{
				key: "f8YjkcGgOggYzlIr2KtShY+8ZgR0hIXmJHPjCG8wi2Q=",
				ip:  "dcf1:4e76:15bd:b2c7",
				urls: []string{
					"http://rjokstglnmpce.localhost.com",
					"http://fccadcf14e7615bdb2c7638238302374.localhost.com",
				},
			},
			{
				key: "Q3dubFlwwLnCpQTagjCckb1XLGtViZoBX1qHAZWV2gI=",
				ip:  "25a2:8a43:2e91:1543",
				urls: []string{
					"http://4mh8kgpei4ak6.localhost.com",
					"http://fcca25a28a432e9115439264ae85af84.localhost.com",
				},
			},
		}

		for i, c := range cases {
			i, c := i, c

			pubKey, err := wgtypes.ParseKey(c.key)
			require.NoError(t, err)

			t.Run(fmt.Sprintf("Default/%d", i), func(t *testing.T) {
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

				expectedIP := "fcca::" + c.ip

				ip, urls := options.WireguardPublicKeyToIPAndURLs(device.NoisePublicKey(pubKey), tunnelsdk.TunnelVersion2)
				require.Equal(t, expectedIP, ip.String())

				urlsStr := make([]string, len(urls))
				for i, u := range urls {
					urlsStr[i] = u.String()
				}
				require.Equal(t, c.urls, urlsStr)

				// Try the old version, which should have a reversed URL list.
				ip, urls = options.WireguardPublicKeyToIPAndURLs(device.NoisePublicKey(pubKey), tunnelsdk.TunnelVersion1)
				require.Equal(t, expectedIP, ip.String())

				urlsStr = make([]string, len(urls))
				for i, u := range urls {
					urlsStr[len(urls)-i-1] = u.String()
				}
				require.Equal(t, c.urls, urlsStr)
			})

			t.Run(fmt.Sprintf("LongerPrefix/%d", i), func(t *testing.T) {
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

				expectedIP := "feed:beef:deaf:deed:" + c.ip

				// The second URL has a different IP prefix length, so adjust
				// accordingly.
				expectedURL2, err := url.Parse(c.urls[1])
				require.NoError(t, err)
				hostRest := strings.SplitN(expectedURL2.Host, ".", 2)[1]
				expectedURL2.Host = "feedbeefdeafdeed" + expectedURL2.Host[4:20] + "." + hostRest
				t.Logf("mutated URL %q to %q", c.urls[1], expectedURL2.String())
				expectedURLs := []string{
					c.urls[0],
					expectedURL2.String(),
				}

				ip, urls := options.WireguardPublicKeyToIPAndURLs(device.NoisePublicKey(pubKey), tunnelsdk.TunnelVersion2)
				require.Equal(t, expectedIP, ip.String())

				urlsStr := make([]string, len(urls))
				for i, u := range urls {
					urlsStr[i] = u.String()
				}
				require.Equal(t, expectedURLs, urlsStr)

				// Try the old version, which should have a reversed URL list.
				ip, urls = options.WireguardPublicKeyToIPAndURLs(device.NoisePublicKey(pubKey), tunnelsdk.TunnelVersion1)
				require.Equal(t, expectedIP, ip.String())

				urlsStr = make([]string, len(urls))
				for i, u := range urls {
					urlsStr[len(urls)-i-1] = u.String()
				}
				require.Equal(t, expectedURLs, urlsStr)
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
			// Good format:
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

			// Good format errors:
			{
				hostname:    "v2vphj9slsv64.localhost.com",
				errContains: "decode new hostname",
			},
			{
				hostname:    "4mh8kgpei4ak64mh8kgpei4ak6",
				errContains: "invalid new hostname length",
			},

			// Bad format:
			{
				hostname: "fccaf8bf98cd3caf3e6270a5db3140f9",
				ip:       "f8bf:98cd:3caf:3e62",
			},
			{
				hostname: "fcca2150c2ea38fe021f76fac00cd533",
				ip:       "2150:c2ea:38fe:21f",
			},
			{
				hostname: "fccac17e72e4c52ea6c4fbb4ef809339",
				ip:       "c17e:72e4:c52e:a6c4",
			},
			{
				hostname: "fccaf7732e08771d7a6f6fdcb4a1f367",
				ip:       "f773:2e08:771d:7a6f",
			},
			{
				hostname: "fccadcf14e7615bdb2c7638238302374",
				ip:       "dcf1:4e76:15bd:b2c7",
			},
			{
				hostname: "fcca25a28a432e9115439264ae85af84",
				ip:       "25a2:8a43:2e91:1543",
			},

			// Bad format errors:
			{
				hostname:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				errContains: "decode old hostname",
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

					// The second hostname has a different IP prefix length, so
					// adjust accordingly.
					hostname := c.hostname
					if len(hostname) == 32 {
						hostname = "feedbeefdeafdeed" + hostname[4:20]
						t.Logf("mutated hostname %q to %q", c.hostname, hostname)
					}

					ip, err := options.HostnameToWireguardIP(hostname)
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
