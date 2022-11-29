package tunnelsdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/xerrors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"cdr.dev/slog"
)

// TunnelPort is the port in the virtual wireguard network stack that the
// listener is listening on.
const TunnelPort = 8080

// Key is a Wireguard private or public key.
type Key struct {
	k         wgtypes.Key
	isPrivate bool
}

// GenerateWireguardPrivateKey generates a new wireguard private key using
// secure cryptography. The caller should store the key (using key.String()) in
// a safe place like the user's home directory, and use it in the future rather
// than generating a new key each time.
func GeneratePrivateKey() (Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Key{}, err
	}

	return Key{
		k:         key,
		isPrivate: true,
	}, nil
}

// ParsePrivateKey parses a private key generated using key.String().
func ParsePrivateKey(key string) (Key, error) {
	k, err := wgtypes.ParseKey(key)
	if err != nil {
		return Key{}, err
	}

	return Key{
		k: k,
		// assume it's private, not really any way to tell unfortunately
		isPrivate: true,
	}, nil
}

// IsZero returns true if the Key is the zero value.
func (k Key) IsZero() bool {
	return k.k == wgtypes.Key{}
}

// IsPrivate returns true if the key is a private key.
func (k Key) IsPrivate() bool {
	return k.isPrivate
}

// String returns a base64 encoded string representation of the key.
func (k Key) String() string {
	return k.k.String()
}

// HexString returns the hex string representation of the key.
func (k Key) HexString() string {
	return hex.EncodeToString(k.k[:])
}

// NoisePrivateKey returns the device.NoisePrivateKey for the key. If the key is
// not a private key, an error is returned.
func (k Key) NoisePrivateKey() (device.NoisePrivateKey, error) {
	if !k.isPrivate {
		return device.NoisePrivateKey{}, xerrors.Errorf("cannot call key.NoisePrivateKey() on a public key")
	}

	return device.NoisePrivateKey(k.k), nil
}

// NoisePublicKey returns the device.NoisePublicKey for the key. If the key is a
// private key, it is converted to a public key automatically.
func (k Key) NoisePublicKey() device.NoisePublicKey {
	if k.isPrivate {
		return device.NoisePublicKey(k.k.PublicKey())
	}

	return device.NoisePublicKey(k.k)
}

// PublicKey returns the public key component of the Wireguard private key. If
// the key is not a private key, an error is returned.
func (k Key) PublicKey() (Key, error) {
	if !k.isPrivate {
		return k, xerrors.Errorf("cannot call key.PublicKey() on a public key")
	}

	return Key{
		k:         k.k.PublicKey(),
		isPrivate: false,
	}, nil
}

type TunnelConfig struct {
	Log slog.Logger
	// PrivateKey is the Wireguard private key. You can use GeneratePrivateKey
	// to generate a new key. It should be stored in a safe place for future
	// tunnel sessions, otherwise you will get a new hostname.
	PrivateKey Key
}

func (c *Client) LaunchTunnel(ctx context.Context, cfg TunnelConfig) (*Tunnel, error) {
	pubKey := cfg.PrivateKey.NoisePublicKey()

	res, err := c.ClientRegister(ctx, ClientRegisterRequest{
		PublicKey: pubKey,
	})
	if err != nil {
		return nil, xerrors.Errorf("initial client registration: %w", err)
	}

	tunnelURL, err := url.Parse(res.TunnelURL)
	if err != nil {
		return nil, xerrors.Errorf("parse tunnel url: %w", err)
	}

	// Ensure the returned server endpoint from the API is an IP address and not
	// a hostname to avoid constant DNS lookups.
	host, port, err := net.SplitHostPort(res.ServerEndpoint)
	if err != nil {
		return nil, xerrors.Errorf("parse server endpoint: %w", err)
	}
	wgIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, xerrors.Errorf("resolve endpoint: %w", err)
	}
	wgEndpoint := net.JoinHostPort(wgIP.String(), port)

	// Start re-registering the client every 30 seconds.
	returnedOK := false
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	defer func() {
		if !returnedOK {
			tunnelCancel()
		}
	}()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-tunnelCtx.Done():
				return
			case <-ticker.C:
			}

			ctx, cancel := context.WithTimeout(tunnelCtx, 10*time.Second)
			_, err := c.ClientRegister(ctx, ClientRegisterRequest{
				PublicKey: pubKey,
			})
			if err != nil && !xerrors.Is(err, context.Canceled) {
				cfg.Log.Warn(ctx, "periodically re-register tunnel", slog.Error(err))
			}
			cancel()
		}
	}()

	// Create wireguard virtual network stack.
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{res.ClientIP},
		// We don't resolve hostnames in the tunnel, so we don't need a DNS
		// server.
		[]netip.Addr{},
		res.WireguardMTU,
	)
	if err != nil {
		return nil, xerrors.Errorf("create net TUN: %w", err)
	}

	// Create wireguard device, configure it and start it.
	deviceLogger := cfg.Log.Named("wireguard_device")
	dlog := &device.Logger{
		Verbosef: func(format string, args ...any) {
			deviceLogger.Debug(ctx, fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			deviceLogger.Error(ctx, fmt.Sprintf(format, args...))
		},
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), dlog)
	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=21
allowed_ip=%s/128`,
		cfg.PrivateKey.HexString(),
		hex.EncodeToString(res.ServerPublicKey[:]),
		wgEndpoint,
		res.ServerIP.String(),
	))
	if err != nil {
		return nil, xerrors.Errorf("configure wireguard ipc: %w", err)
	}
	err = dev.Up()
	if err != nil {
		return nil, xerrors.Errorf("wireguard device up: %w", err)
	}

	// Create a listener on the static tunnel port.
	wgListen, err := tnet.ListenTCP(&net.TCPAddr{Port: TunnelPort})
	if err != nil {
		return nil, xerrors.Errorf("wireguard device listen: %w", err)
	}

	closed := make(chan struct{}, 1)
	closeFn := func() {
		tunnelCancel()

		_ = wgListen.Close()
		// Remove peers before closing to avoid a race condition between
		// dev.Close() and the peer goroutines which results in segfault.
		dev.RemoveAllPeers()
		dev.Close()
	}
	go func() {
		defer close(closed)
		select {
		case <-ctx.Done():
			closeFn()
		case <-dev.Wait():
			tunnelCancel()
		}
	}()

	returnedOK = true
	return &Tunnel{
		closeFn:  closeFn,
		closed:   closed,
		URL:      tunnelURL,
		Listener: wgListen,
	}, nil
}

type Tunnel struct {
	closeFn  func()
	closed   <-chan struct{}
	URL      *url.URL
	Listener net.Listener
}

func (t *Tunnel) Close() error {
	t.closeFn()
	return nil
}

func (t *Tunnel) Wait() <-chan struct{} {
	return t.closed
}
