package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/urfave/cli/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sync/errgroup"
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
				EnvVars: []string{"TUNNELD_WIREGUARD_SERVER_IP"},
			},
			&cli.StringFlag{
				Name:    "wireguard-network-prefix",
				Aliases: []string{"wg-network-prefix"},
				Usage:   "The CIDR of the wireguard network. All client IPs will be generated within this network. Must be a IPv6 CIDR and have at least 64 bits available.",
				Value:   tunneld.DefaultWireguardNetworkPrefix.String(),
				EnvVars: []string{"TUNNELD_WIREGUARD_NETWORK_PREFIX"},
			},
			&cli.StringFlag{
				Name:    "pprof-listen-address",
				Usage:   "The address to listen on for pprof. If set to an empty string, pprof will not be enabled.",
				Value:   "127.0.0.1:6060",
				EnvVars: []string{"TUNNELD_PPROF_LISTEN_ADDRESS"},
			},
			&cli.StringFlag{
				Name:    "tracing-honeycomb-team",
				Usage:   "The Honeycomb team ID to send tracing data to. If not specified, tracing will not be shipped anywhere.",
				EnvVars: []string{"TUNNELD_TRACING_HONEYCOMB_TEAM"},
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
		pprofListenAddress     = ctx.String("pprof-listen-address")
		tracingHoneycombTeam   = ctx.String("tracing-honeycomb-team")
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

	// Initiate tracing.
	var tp *sdktrace.TracerProvider
	if tracingHoneycombTeam != "" {
		exp, err := newHoneycombExporter(ctx.Context, tracingHoneycombTeam)
		if err != nil {
			return xerrors.Errorf("failed to create honeycomb telemetry exporter: %w", err)
		}

		// Create a new tracer provider with a batch span processor and the otlp
		// exporter.
		tp := newTraceProvider(exp)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(
			propagation.NewCompositeTextMapPropagator(
				propagation.TraceContext{},
				propagation.Baggage{},
			),
		)

		defer func() {
			// allow time for traces to flush even if command context is canceled
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(ctx)
		}()
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
	if tp != nil {
		server.Handler = otelhttp.NewHandler(server.Handler, "tunneld")
	}

	// Start the pprof server if requested.
	if pprofListenAddress != "" {
		var _ = pprof.Handler
		go func() {
			server := &http.Server{
				// See above for why we discard these errors.
				ErrorLog:          log.New(io.Discard, "", 0),
				ReadHeaderTimeout: 15 * time.Second,
				Addr:              pprofListenAddress,
				Handler:           nil, // use pprof
			}

			logger.Info(ctx.Context, "starting pprof server", slog.F("listen_address", pprofListenAddress))
			_ = server.ListenAndServe()
		}()
	}

	eg, egCtx := errgroup.WithContext(ctx.Context)
	eg.Go(func() error {
		logger.Info(egCtx, "listening for requests", slog.F("listen_address", listenAddress))
		err = server.ListenAndServe()
		if err != nil {
			return xerrors.Errorf("error in ListenAndServe: %w", err)
		}
		return nil
	})

	notifyCtx, notifyStop := signal.NotifyContext(ctx.Context, InterruptSignals...)
	defer notifyStop()

	eg.Go(func() error {
		<-notifyCtx.Done()
		logger.Info(egCtx, "shutting down server due to signal")

		shutdownCtx, shutdownCancel := context.WithTimeout(egCtx, 5*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	})

	return eg.Wait()
}
