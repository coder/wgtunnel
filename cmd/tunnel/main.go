package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"cdr.dev/slog"
	"cdr.dev/slog/sloggers/sloghuman"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"github.com/coder/wgtunnel/cmdflags"
	"github.com/coder/wgtunnel/tunnelsdk"
)

func main() {
	var (
		showHelp         bool
		verbose          bool
		targetAddress    string
		apiURL           string
		wireguardKey     string
		wireguardKeyFile string
	)
	cmdflags.BoolFlag(&showHelp, "help", "TUNNEL_HELP", false, "Show this help text.")
	cmdflags.BoolFlag(&verbose, "verbose", "TUNNEL_VERBOSE", false, "Enable verbose logging.")
	cmdflags.StringFlag(&targetAddress, "target-address", "TUNNEL_TARGET_ADDRESS", "", "The address of the target server to tunnel to.")
	cmdflags.StringFlag(&apiURL, "api-url", "TUNNEL_API_URL", "", "The base URL of the tunnel API.")
	cmdflags.StringFlag(&wireguardKey, "wireguard-key", "TUNNEL_WIREGUARD_KEY", "", "The private key for the wireguard client. It should be base64 encoded. You must specify this or wireguard-key-file.")
	cmdflags.StringFlag(&wireguardKeyFile, "wireguard-key-file", "TUNNEL_WIREGUARD_KEY_FILE", "", "The file containing the private key for the wireguard client. It should contain a base64 encoded key. The file will be created and populated with a fresh key if it does not exist. You must specify this or wireguard-key.")

	pflag.Parse()
	if showHelp {
		pflag.Usage()
		os.Exit(1)
	}
	if targetAddress == "" {
		log.Println("target-address or TUNNEL_TARGET_ADDRESS is required.")
		showHelp = true
	}
	if apiURL == "" {
		log.Println("api-url or TUNNEL_API_URL is required.")
		showHelp = true
	}
	if wireguardKey == "" || wireguardKeyFile == "" {
		log.Println("wireguard-key, TUNNEL_WIREGUARD_KEY, wireguard-key-file, or TUNNEL_WIREGUARD_KEY_FILE is required.")
		showHelp = true
	}
	if wireguardKey != "" && wireguardKeyFile != "" {
		log.Println("Either wireguard-key, TUNNEL_WIREGUARD_KEY, wireguard-key-file, or TUNNEL_WIREGUARD_KEY_FILE can be supplied, not multiple.")
		showHelp = true
	}
	if showHelp {
		pflag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.Make(sloghuman.Sink(os.Stderr)).Leveled(slog.LevelInfo)
	if verbose {
		logger = logger.Leveled(slog.LevelDebug)
	}

	apiURLParsed, err := url.Parse(apiURL)
	if err != nil {
		log.Fatalf("Invalid api-url or TUNNEL_API_URL %q: %+v", apiURL, err)
	}

	if wireguardKeyFile != "" {
		fileBytes, err := os.ReadFile(wireguardKeyFile)
		if xerrors.Is(err, os.ErrNotExist) {
			key, err := tunnelsdk.GeneratePrivateKey()
			if err != nil {
				log.Fatalf("Failed to generate wireguard key: %+v", err)
			}

			fileBytes = []byte(key.String())
			err = os.WriteFile(wireguardKeyFile, fileBytes, 0600)
			if err != nil {
				log.Fatalf("Failed to write wireguard key to file %q: %+v", wireguardKeyFile, err)
			}
		} else if err != nil {
			log.Fatalf("Failed to read wireguard-key-file or TUNNEL_WIREGUARD_KEY_FILE %q: %+v", wireguardKeyFile, err)
		}
		wireguardKey = string(fileBytes)
	}

	wireguardKeyParsed, err := tunnelsdk.ParsePrivateKey(wireguardKey)
	if err != nil {
		log.Fatalf("Invalid wireguard-key, TUNNEL_WIREGUARD_KEY, wireguard-key-file, or TUNNEL_WIREGUARD_KEY_FILE %q: %+v", wireguardKey, err)
	}

	client := tunnelsdk.New(apiURLParsed)
	tunnel, err := client.LaunchTunnel(ctx, tunnelsdk.TunnelConfig{
		Log:        logger,
		PrivateKey: wireguardKeyParsed,
	})
	if err != nil {
		log.Fatalf("Failed to launch tunnel: %+v", err)
	}
	defer func() {
		err := tunnel.Close()
		if err != nil {
			log.Fatalf("Failed to close tunnel: %+v", err)
		}
	}()

	// Start forwarding traffic to/from the tunnel.
	go func() {
		for {
			conn, err := tunnel.Listener.Accept()
			if err != nil {
				log.Fatalf("Failed to accept connection: %+v", err)
			}

			go func() {
				defer conn.Close()

				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				targetConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddress)
				if err != nil {
					log.Printf("Failed to dial target %q: %+v", targetAddress, err)
					return
				}
				defer targetConn.Close()

				go func() {
					_, err := io.Copy(targetConn, conn)
					if err != nil {
						log.Printf("Failed to copy from tunnel to target: %+v", err)
					}
				}()

				_, err = io.Copy(conn, targetConn)
			}()
		}
	}()

	// TODO: manual signal handling
	<-tunnel.Wait()
}
