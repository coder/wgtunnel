package main

import (
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/coder/wgtunnel/buildinfo"
	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func main() {
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"V"},
		Usage:   "Print the version.",
	}

	app := &cli.App{
		Name:    "tunneld",
		Usage:   "run a wgtunnel server",
		Version: buildinfo.Version(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose logging.",
				EnvVars: []string{"TUNNELD_VERBOSE"},
			},
			&cli.StringFlag{
				Name:    "listen-address",
				Aliases: []string{"a"},
				Usage:   "HTTP listen address for the API and tunnel traffic.",
				Value:   "127.0.0.1:8080",
				EnvVars: []string{"TUNNELD_LISTEN_ADDRESS"},
			},
			&cli.StringFlag{
				Name:    "base-url",
				Aliases: []string{"u"},
				Usage:   "The base URL to use for the tunnel, including scheme. All tunnels will be subdomains of this hostname.",
				EnvVars: []string{"TUNNELD_BASE_URL"},
			},
			&cli.StringFlag{
				Name:    "wireguard-endpoint",
				Aliases: []string{"wg-endpoint"},
				Usage:   "The UDP address advertised to clients that they will connect to for wireguard connections. It should be in the form host:port.",
				EnvVars: []string{"TUNNELD_WIREGUARD_ENDPOINT"},
			},
			// Technically a uint16.
			&cli.UintFlag{
				Name:    "wireguard-port",
				Aliases: []string{"wg-port"},
				Usage:   "The UDP port that the wireguard server will listen on. It should be the same as the port in wireguard-endpoint.",
				EnvVars: []string{"TUNNELD_WIREGUARD_PORT"},
			},
			&cli.StringFlag{
				Name:    "wireguard-key",
				Aliases: []string{"wg-key"},
				Usage:   "The private key for the wireguard server. It should be base64 encoded.",
				EnvVars: []string{"TUNNELD_WIREGUARD_KEY"},
			},
			&cli.IntFlag{
				Name:    "wireguard-mtu",
				Aliases: []string{"wg-mtu"},
				Usage:   "The MTU to use for the wireguard interface.",
				Value:   tunneld.DefaultWireguardMTU,
				EnvVars: []string{"TUNNELD_WIREGUARD_MTU"},
			},
			&cli.StringFlag{
				Name:    "wireguard-server-ip",
				Aliases: []string{"wg-server-ip"},
				Usage:   "The virtual IP address of this server in the wireguard network. Must be an IPv6 address contained within wireguard-network-prefix.",
				Value:   tunneld.DefaultWireguardServerIP.String(),
			},
			&cli.StringFlag{
				Name:    "wireguard-network-prefix",
				Aliases: []string{"wg-network-prefix"},
				Usage:   "The CIDR of the wireguard network. All client IPs will be generated within this network. Must be a IPv6 CIDR and have at least 64 bits available.",
				Value:   tunneld.DefaultWireguardNetworkPrefix.String(),
			},
		},
		Action: runApp,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func runApp(ctx *cli.Context) error {
	var (
		verbose                = ctx.Bool("verbose")
		listenAddress          = ctx.String("listen-address")
		baseURL                = ctx.String("base-url")
		wireguardEndpoint      = ctx.String("wireguard-endpoint")
		wireguardPort          = ctx.Uint("wireguard-port")
		wireguardKey           = ctx.String("wireguard-key")
		wireguardMTU           = ctx.Int("wireguard-mtu")
		wireguardServerIP      = ctx.String("wireguard-server-ip")
		wireguardNetworkPrefix = ctx.String("wireguard-network-prefix")
	)
	if baseURL == "" {
		return xerrors.New("base-hostname is required. See --help for more information.")
	}
	if wireguardEndpoint == "" {
		return xerrors.New("wireguard-endpoint is required. See --help for more information.")
	}
	if wireguardPort < 1 || wireguardPort > 65535 {
		return xerrors.New("wireguard-port is required and must be between 1 and 65535. See --help for more information.")
	}
	if wireguardKey == "" {
		return xerrors.New("wireguard-key is required. See --help for more information.")
	}

	logger := slog.Make(sloghuman.Sink(os.Stderr)).Leveled(slog.LevelInfo)
	if verbose {
		logger = logger.Leveled(slog.LevelDebug)
	}

	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		return xerrors.Errorf("could not parse base-url %q: %w", baseURL, err)
	}
	wireguardKeyParsed, err := tunnelsdk.ParsePrivateKey(wireguardKey)
	if err != nil {
		return xerrors.Errorf("could not parse wireguard-key %q: %w", wireguardKey, err)
	}
	wireguardServerIPParsed, err := netip.ParseAddr(wireguardServerIP)
	if err != nil {
		return xerrors.Errorf("could not parse wireguard-server-ip %q: %w", wireguardServerIP, err)
	}
	wireguardNetworkPrefixParsed, err := netip.ParsePrefix(wireguardNetworkPrefix)
	if err != nil {
		return xerrors.Errorf("could not parse wireguard-network-prefix %q: %w", wireguardNetworkPrefix, err)
	}

	options := &tunneld.Options{
		BaseURL:                baseURLParsed,
		WireguardEndpoint:      wireguardEndpoint,
		WireguardPort:          uint16(wireguardPort),
		WireguardKey:           wireguardKeyParsed,
		WireguardMTU:           wireguardMTU,
		WireguardServerIP:      wireguardServerIPParsed,
		WireguardNetworkPrefix: wireguardNetworkPrefixParsed,
	}
	td, err := tunneld.New(options)
	if err != nil {
		return xerrors.Errorf("create tunneld.API instance: %w", err)
	}

	// ReadHeaderTimeout is purposefully not enabled. It caused some issues with
	// websockets over the dev tunnel.
	// See: https://github.com/coder/coder/pull/3730
	//nolint:gosec
	server := &http.Server{
		// These errors are typically noise like "TLS: EOF". Vault does similar:
		// https://github.com/hashicorp/vault/blob/e2490059d0711635e529a4efcbaa1b26998d6e1c/command/server.go#L2714
		ErrorLog: log.New(io.Discard, "", 0),
		Addr:     listenAddress,
		Handler:  td.Router(),
	}

	logger.Info(ctx.Context, "listening for requests", slog.F("listen_address", listenAddress))
	err = server.ListenAndServe()
	if err != nil {
		return xerrors.Errorf("error in ListenAndServe: %w", err)
	}

	// TODO: manual signal handling
	return nil
}
