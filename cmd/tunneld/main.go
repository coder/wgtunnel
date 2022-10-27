package main

import (
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"

	"github.com/spf13/pflag"

	"github.com/coder/wgtunnel/cmdflags"
	"github.com/coder/wgtunnel/tunneld"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func main() {
	var (
		showHelp               bool
		listenAddress          string
		baseURL                string
		wireguardEndpoint      string
		wireguardPort          uint16
		wireguardKey           string
		wireguardMTU           int
		wireguardServerIP      string
		wireguardNetworkPrefix string
	)
	cmdflags.BoolFlag(&showHelp, "help", "TUNNELD_HELP", false, "Show this help text.")
	cmdflags.StringFlag(&listenAddress, "listen-address", "TUNNELD_LISTEN_ADDRESS", "127.0.0.1:8080", "HTTP listen address for the API and tunnel traffic.")
	cmdflags.StringFlag(&baseURL, "base-url", "TUNNELD_BASE_URL", "", "The base URL to use for the tunnel, including scheme. All tunnels will be subdomains of this hostname.")
	cmdflags.StringFlag(&wireguardEndpoint, "wireguard-endpoint", "TUNNELD_WIREGUARD_ENDPOINT", "", "The UDP address advertised to clients that they will connect to for wireguard connections. It should be in the form host:port.")
	cmdflags.Uint16Flag(&wireguardPort, "wireguard-port", "TUNNELD_WIREGUARD_PORT", 0, "The UDP port that the wireguard server will listen on. It should be the same as the port in wireguard-endpoint.")
	cmdflags.StringFlag(&wireguardKey, "wireguard-key", "TUNNELD_WIREGUARD_KEY", "", "The private key for the wireguard server. It should be base64 encoded.")
	cmdflags.IntFlag(&wireguardMTU, "wireguard-mtu", "TUNNELD_WIREGUARD_MTU", 1280, "The MTU to use for the wireguard interface.")
	cmdflags.StringFlag(&wireguardServerIP, "wireguard-server-ip", "TUNNELD_WIREGUARD_SERVER_IP", tunneld.DefaultWireguardServerIP.String(), "The virtual IP address of this server in the wireguard network. Must be an IPv6 address contained within wireguard-network-prefix.")
	cmdflags.StringFlag(&wireguardNetworkPrefix, "wireguard-network-prefix", "TUNNELD_WIREGUARD_NETWORK_PREFIX", tunneld.DefaultWireguardNetworkPrefix.String(), "The CIDR of the wireguard network. All client IPs will be generated within this network. Must be a IPv6 CIDR and have at least 64 bits available.")

	pflag.Parse()
	if showHelp {
		pflag.Usage()
		os.Exit(1)
	}
	if baseURL == "" {
		log.Println("base-hostname or TUNNELD_BASE_HOSTNAME is required.")
		showHelp = true
	}
	if wireguardEndpoint == "" {
		log.Println("wireguard-endpoint or TUNNELD_WIREGUARD_ENDPOINT is required.")
		showHelp = true
	}
	if wireguardPort == 0 {
		log.Println("wireguard-port or TUNNELD_WIREGUARD_PORT is required.")
		showHelp = true
	}
	if wireguardKey == "" {
		log.Println("wireguard-key or TUNNELD_WIREGUARD_KEY is required.")
		showHelp = true
	}
	if showHelp {
		pflag.Usage()
		os.Exit(1)
	}

	baseURLParsed, err := url.Parse(baseURL)
	if err != nil {
		log.Fatalf("Invalid base-url or TUNNELD_BASE_URL %q: %+v", baseURL, err)
	}
	wireguardKeyParsed, err := tunnelsdk.ParsePrivateKey(wireguardKey)
	if err != nil {
		log.Fatalf("Invalid wireguard-key or TUNNELD_WIREGUARD_KEY %q: %+v", wireguardKey, err)
	}
	wireguardServerIPParsed, err := netip.ParseAddr(wireguardServerIP)
	if err != nil {
		log.Fatalf("Invalid wireguard-server-ip or TUNNELD_WIREGUARD_SERVER_IP %q: %+v", wireguardServerIP, err)
	}
	wireguardNetworkPrefixParsed, err := netip.ParsePrefix(wireguardNetworkPrefix)
	if err != nil {
		log.Fatalf("Invalid wireguard-network-prefix or TUNNELD_WIREGUARD_NETWORK_PREFIX %q: %+v", wireguardNetworkPrefix, err)
	}

	options := &tunneld.Options{
		BaseURL:                baseURLParsed,
		WireguardEndpoint:      wireguardEndpoint,
		WireguardPort:          wireguardPort,
		WireguardKey:           wireguardKeyParsed,
		WireguardMTU:           wireguardMTU,
		WireguardServerIP:      wireguardServerIPParsed,
		WireguardNetworkPrefix: wireguardNetworkPrefixParsed,
	}
	td, err := tunneld.New(options)
	if err != nil {
		log.Fatalf("Failed to create new tunneld instance: %+v", err)
	}

	server := &http.Server{
		Addr:    listenAddress,
		Handler: td.Router(),
	}

	log.Printf("Listening on %s", listenAddress)
	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Error in ListenAndServe: %+v", err)
	}

	// TODO: manual signal handling
}
