# wgtunnel

wgtunnel is a simple WireGuard tunnel server. Clients can register themselves
to the server with a single API request (done periodically in the background in
case the server restarts), and then connect to a WireGuard endpoint on the
server over UDP to tunnel.

Generated URLs are unique and are based on the WireGuard public key. Wildcards
for each tunnel are also semi-supported, using hyphens instead of periods to
allow for TLS.

This is used by [Coder](https://github.com/coder/coder) to create tunnels for
trial/demo deployments with globally accessible URLs.

## Deployment

Deploy `tunneld` onto your server and configure it with environment variables or
flags. Point the DNS entries `${base_url}` and `*.${base_url}` to the server. If
you want to use HTTPS, setup a proxy such as [Caddy](https://caddyserver.com/)
in front of the server.

`tunneld` is available on GitHub releases or can be installed with:

```console
$ go install github.com/coder/wgtunnel/cmd/tunneld
```

or by running `make build/tunneld`.

You can also use the Docker image `ghcr.io/coder/wgtunnel/tunneld`.

## Usage

Either use `tunnel` for easy usage from a terminal, or use the `tunnelsdk`
package to initiate a tunnel against the given API server URL. Remember to
store the private key for future tunnel sessions in a safe place, otherwise you
will get a new hostname!

`tunnel` can be installed with:

```console
$ go install github.com/coder/wgtunnel/cmd/tunnel
```

or by running `make build/tunnel`.

## License

Licensed under the AGPL-3.0 license.
