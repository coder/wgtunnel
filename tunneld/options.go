package tunneld

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"github.com/coder/wgtunnel/tunnelsdk"
)

const (
	DefaultWireguardMTU     = 1280
	DefaultPeerDialTimeout  = 10 * time.Second
	DefaultPeerPollDuration = 30 * time.Second
	DefaultPeerTimeout      = 2 * time.Minute
)

var (
	DefaultWireguardServerIP      = netip.MustParseAddr("fcca::1")
	DefaultWireguardNetworkPrefix = netip.MustParsePrefix("fcca::/16")
)

var newHostnameEncoder = base32.HexEncoding.WithPadding(base32.NoPadding)

type Options struct {
	Log slog.Logger

	// BaseURL is the base URL to use for the tunnel, including scheme. All
	// tunnels will be subdomains of this hostname.
	// e.g. "https://tunnel.example.com" will place tunnels at
	//      "https://xyz.tunnel.example.com"
	BaseURL *url.URL

	// WireguardEndpoint is the UDP address advertised to clients that they will
	// connect to for wireguard connections. It should be in the form
	// "$ip:$port" or "$hostname:$port".
	WireguardEndpoint string
	// WireguardPort is the UDP port that the wireguard server will listen on.
	// It should be the same as the port in WireguardEndpoint.
	WireguardPort uint16
	// WireguardKey is the private key for the wireguard server.
	WireguardKey tunnelsdk.Key

	// WireguardMTU is the MTU to use for the wireguard interface. Defaults to
	// 1280.
	WireguardMTU int
	// WireguardServerIP is the virtual IP address of this server in the
	// wireguard network. Must be an IPv6 address contained within
	// WireguardNetworkPrefix. Defaults to fcca::1.
	WireguardServerIP netip.Addr
	// WireguardNetworkPrefix is the CIDR of the wireguard network. All client
	// IPs will be generated within this network. Must be a IPv6 CIDR and have
	// at least 64 bits of space available. Defaults to fcca::/16.
	WireguardNetworkPrefix netip.Prefix

	// RealIPHeader is the header to use for getting a request's IP address. If
	// not set, the request's RemoteAddr will be used.
	//
	// Used for rate limiting.
	RealIPHeader string

	// PeerDialTimeout is the timeout for dialing a peer on a request. Defaults
	// to 10 seconds.
	PeerDialTimeout time.Duration

	// PeerRegisterInterval is how often the clients should re-register.
	PeerRegisterInterval time.Duration

	// PeerTimeout is how long the server will wait before removing the peer.
	PeerTimeout time.Duration
}

// Validate checks that the options are valid and populates default values for
// missing fields.
func (options *Options) Validate() error {
	if options == nil {
		return xerrors.New("options is nil")
	}
	if options.BaseURL == nil {
		return xerrors.New("BaseURL is required")
	}
	if options.WireguardEndpoint == "" {
		return xerrors.New("WireguardEndpoint is required")
	}
	_, _, err := net.SplitHostPort(options.WireguardEndpoint)
	if err != nil {
		return xerrors.Errorf("WireguardEndpoint %q is not a valid host:port combination: %w", options.WireguardEndpoint, err)
	}
	if options.WireguardPort == 0 {
		return xerrors.New("WireguardPort is required")
	}
	if options.WireguardKey.IsZero() {
		return xerrors.New("WireguardKey is required")
	}
	if !options.WireguardKey.IsPrivate() {
		return xerrors.New("WireguardKey must be a private key")
	}
	// Key is parsed and validated when the server is started.
	if options.WireguardMTU <= 0 {
		options.WireguardMTU = DefaultWireguardMTU
	}
	if options.WireguardServerIP.BitLen() == 0 {
		options.WireguardServerIP = DefaultWireguardServerIP
	}
	if options.WireguardServerIP.BitLen() != 128 {
		return xerrors.New("WireguardServerIP must be an IPv6 address")
	}
	if options.WireguardNetworkPrefix.Bits() <= 0 {
		options.WireguardNetworkPrefix = DefaultWireguardNetworkPrefix
	}
	if options.WireguardNetworkPrefix.Bits() > 64 {
		return xerrors.New("WireguardNetworkPrefix must have at least 64 bits available")
	}
	if options.WireguardNetworkPrefix.Bits()%8 != 0 {
		return xerrors.New("WireguardNetworkPrefix must be a multiple of 8 bits")
	}
	if !options.WireguardNetworkPrefix.Contains(options.WireguardServerIP) {
		return xerrors.New("WireguardServerIP must be contained within WireguardNetworkPrefix")
	}

	if options.RealIPHeader != "" {
		options.RealIPHeader = http.CanonicalHeaderKey(options.RealIPHeader)
	}

	if options.PeerDialTimeout <= 0 {
		options.PeerDialTimeout = DefaultPeerDialTimeout
	}
	if options.PeerRegisterInterval <= 0 {
		options.PeerRegisterInterval = DefaultPeerPollDuration
	}
	if options.PeerTimeout <= 0 {
		options.PeerTimeout = DefaultPeerTimeout
	}
	if options.PeerRegisterInterval >= options.PeerTimeout {
		return xerrors.Errorf("PeerRegisterInterval(%s) must be less than PeerTimeout(%s)",
			options.PeerRegisterInterval.String(),
			options.PeerTimeout.String(),
		)
	}

	return nil
}

// WireguardPublicKeyToIPAndURLs returns the IP address that corresponds to the
// given wireguard public key, as well as all accepted tunnel URLs for the key.
//
// We support an older 32 character format ("old format") and a newer 12
// character format ("good format") which is preferred. The first URL returned
// should be considered "preferred", and all other URLs are provided for
// compatibility with older deployments only. The "good format" is preferred as
// it's shorter to avoid issues with hostname length limits when apps prefixes
// are added to the equation.
//
// "good format":
//
//	Take the first 8 bytes of the hash of the public key, and convert to
//	base32.
//
// "old format":
//
//	Take the network prefix, and create a new address filling the last n bytes
//	with the first n bytes of the hash of the public key. Then convert to hex.
func (options *Options) WireguardPublicKeyToIPAndURLs(publicKey device.NoisePublicKey, version tunnelsdk.TunnelVersion) (netip.Addr, []*url.URL) {
	var (
		keyHash   = sha256.Sum256(publicKey[:])
		addrBytes = options.WireguardNetworkPrefix.Addr().As16()
	)

	// IPv6 address:
	// For the IP address, we take the first 64 bits of the network prefix and
	// the first 64 bits of the hash of the public key.
	copy(addrBytes[8:], keyHash[:8])

	// Good format:
	goodFormatBytes := make([]byte, 8)
	copy(goodFormatBytes, keyHash[:8])
	goodFormat := newHostnameEncoder.EncodeToString(goodFormatBytes)
	goodFormatURL := *options.BaseURL
	goodFormatURL.Host = strings.ToLower(goodFormat) + "." + goodFormatURL.Host

	// Old format:
	oldFormatBytes := make([]byte, 16)
	copy(oldFormatBytes, addrBytes[:])
	prefixLenBytes := options.WireguardNetworkPrefix.Bits() / 8
	copy(oldFormatBytes[prefixLenBytes:], keyHash[:16-prefixLenBytes])
	oldFormat := hex.EncodeToString(oldFormatBytes)
	oldFormatURL := *options.BaseURL
	oldFormatURL.Host = strings.ToLower(oldFormat) + "." + oldFormatURL.Host

	urls := []*url.URL{&goodFormatURL, &oldFormatURL}
	if version == tunnelsdk.TunnelVersion1 {
		// Return the old format first for backwards compatibility.
		urls = []*url.URL{&oldFormatURL, &goodFormatURL}
	}

	return netip.AddrFrom16(addrBytes), urls
}

// HostnameToWireguardIP returns the wireguard IP address that corresponds to a
// given encoded hostname label as returned by WireguardPublicKeyToIPAndURLs.
func (options *Options) HostnameToWireguardIP(hostname string) (netip.Addr, error) {
	var addrLast8Bytes []byte

	if len(hostname) == 32 {
		// "Old format":
		decoded, err := hex.DecodeString(hostname)
		if err != nil {
			return netip.Addr{}, xerrors.Errorf("decode old hostname %q as hex: %w", hostname, err)
		}
		if len(decoded) != 16 {
			return netip.Addr{}, xerrors.Errorf("invalid old hostname length: got %d, expected 16", len(decoded))
		}

		// Even though the hostname will have the entire old IP address, we only
		// care about the first 8 bytes after the prefix length.
		prefixLenBytes := options.WireguardNetworkPrefix.Bits() / 8
		addrLast8Bytes = decoded[prefixLenBytes : prefixLenBytes+8]
	} else {
		// "Good format":
		decoded, err := newHostnameEncoder.DecodeString(strings.ToUpper(hostname))
		if err != nil {
			return netip.Addr{}, xerrors.Errorf("decode new hostname %q as base32: %w", hostname, err)
		}
		if len(decoded) != 8 {
			return netip.Addr{}, xerrors.Errorf("invalid new hostname length: got %d, expected 8", len(decoded))
		}

		addrLast8Bytes = decoded
	}

	if addrLast8Bytes == nil {
		return netip.Addr{}, xerrors.Errorf("invalid hostname %q, does not match new or old format", hostname)
	}

	addrBytes := options.WireguardNetworkPrefix.Addr().As16()
	copy(addrBytes[8:], addrLast8Bytes[:])
	return netip.AddrFrom16(addrBytes), nil
}
