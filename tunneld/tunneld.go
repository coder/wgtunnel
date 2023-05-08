package tunneld

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/xerrors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TODO: add logging to API
type API struct {
	*Options

	wgNet     *netstack.Net
	wgDevice  *device.Device
	transport *http.Transport

	pkeyCacheMu sync.RWMutex
	pkeyCache   map[netip.Addr]cachedPeer
}

type cachedPeer struct {
	key           device.NoisePublicKey
	lastHandshake time.Time
}

func New(options *Options) (*API, error) {
	if options == nil {
		options = &Options{}
	}
	err := options.Validate()
	if err != nil {
		return nil, xerrors.Errorf("invalid options: %w", err)
	}

	// Create the wireguard virtual TUN adapter and netstack.
	tun, wgNet, err := netstack.CreateNetTUN(
		[]netip.Addr{options.WireguardServerIP},
		// We don't do DNS resolution over the netstack, so don't specify any
		// DNS servers.
		[]netip.Addr{},
		options.WireguardMTU,
	)
	if err != nil {
		return nil, xerrors.Errorf("create wireguard virtual TUN adapter and netstack: %w", err)
	}

	// Create, configure and start the wireguard device.
	deviceLogger := options.Log.Named("wireguard_device")
	dlog := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			deviceLogger.Debug(context.Background(), fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...interface{}) {
			deviceLogger.Error(context.Background(), fmt.Sprintf(format, args...))
		},
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), dlog)
	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
listen_port=%d`,
		options.WireguardKey.HexString(),
		options.WireguardPort,
	))
	if err != nil {
		return nil, xerrors.Errorf("configure wireguard device: %w", err)
	}
	err = dev.Up()
	if err != nil {
		return nil, xerrors.Errorf("start wireguard device: %w", err)
	}

	return &API{
		Options:   options,
		wgNet:     wgNet,
		wgDevice:  dev,
		pkeyCache: make(map[netip.Addr]cachedPeer),
		transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (nc net.Conn, err error) {
				ctx, span := otel.GetTracerProvider().Tracer("").Start(ctx, "(http.Transport).DialContext")
				defer span.End()
				defer func() {
					if err != nil {
						span.RecordError(err)
						span.SetStatus(codes.Error, err.Error())
					}
				}()

				ip := ctx.Value(ipPortKey{})
				if ip == nil {
					err = xerrors.New("no ip on context")
					return nil, err
				}

				ipp, ok := ip.(netip.AddrPort)
				if !ok {
					err = xerrors.Errorf("ip is incorrect type, got %T", ipp)
					return nil, err
				}

				span.SetAttributes(attribute.String("wireguard_addr", ipp.Addr().String()))

				dialCtx, dialCancel := context.WithTimeout(ctx, options.PeerDialTimeout)
				defer dialCancel()

				nc, err = wgNet.DialContextTCPAddrPort(dialCtx, ipp)
				if err != nil {
					return nil, err
				}

				return nc, nil
			},
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          0,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func (api *API) Close() error {
	// Remove peers before closing to avoid a race condition between dev.Close()
	// and the peer goroutines which results in segfault.
	api.wgDevice.RemoveAllPeers()
	api.wgDevice.Close()
	<-api.wgDevice.Wait()

	return nil
}
