package tunneld

import (
	"fmt"
	"net/netip"

	"golang.org/x/xerrors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TODO: add logging to API and use for the wg device too
type API struct {
	*Options

	wgNet    *netstack.Net
	wgDevice *device.Device
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
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	err = dev.IpcSet(fmt.Sprintf(`
private_key=%s
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
		Options:  options,
		wgNet:    wgNet,
		wgDevice: dev,
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
