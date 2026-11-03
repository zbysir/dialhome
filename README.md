# dialhome

English · [简体中文](README.zh-CN.md)

**Reach your own computer from anywhere**: a cloud relay that only forwards ciphertext.

Your computer (running [herdr-web](https://github.com/zbysir/herdr-web) or gerdr) dials out to dialhome on a VPS.
When your phone opens `https://mac.example.com`, dialhome reads the host name from the TLS handshake (SNI) and hands
the whole connection to that computer **as is**.

- **The relay can't see your traffic.** TLS ends on your own computer, and your computer serves the pages. dialhome
  holds no certificate private keys and none of your login credentials. If someone takes over the whole VPS, the
  most they can do is cut your connection.
- **One command adds a computer.** Make an invite code in the admin page, then run `herdr-web relay join …` on that
  computer (in gerdr, enter it under Settings → Remote access, or run `gerdr remote join`).
- **Every computer has its own identity.** An Ed25519 key pair; the relay stores only the public key. No shared token.
- **Web admin page**: the admin signs in with a passkey, makes invite codes, sees who is online, removes hosts.

How it differs from frp / ngrok / Cloudflare Tunnel: by default the latter two decrypt TLS on their servers. frp's
https passthrough has the same shape as dialhome; what dialhome adds is a per-host identity, joining with one command,
and the admin page. Why it has to work this way: [docs/DESIGN.md](docs/DESIGN.md) §1 (in Chinese).

## Deploy (on the VPS)

```sh
docker run -d --name dialhome --restart unless-stopped \
  -p 443:443 -v dialhome-data:/data \
  -e DIALHOME_DOMAIN=relay.example.com \
  ghcr.io/zbysir/dialhome:latest
```

DNS: point A records at this VPS for `relay.example.com` (the admin page, and where hosts connect) and for every
host's name (`mac.example.com`, or one wildcard such as `*.h.example.com`). dialhome gets the certificate for its own
domain by itself, with TLS-ALPN-01.

Then register the admin passkey:

```sh
docker exec dialhome dialhome admin init
# Open the https://relay.example.com/#setup=… link it prints in a browser and confirm with Face ID / fingerprint
```

From then on, invite hosts in the admin page at `https://relay.example.com/`. The command line does the same:
`dialhome invite <host>` / `dialhome hosts` / `dialhome remove <host>`.

### Configuration (environment variables)

| Variable | Meaning |
|---|---|
| `DIALHOME_DOMAIN` | The relay's own domain (admin page + control plane). Required |
| `DIALHOME_LISTEN` | Listen address, default `:443` |
| `DIALHOME_DIR` | Data directory, default `~/.dialhome` (`/data` in the image) |
| `DIALHOME_TLS_CERT` / `DIALHOME_TLS_KEY` | Certificate for the control plane; without them dialhome gets its own |
| `DIALHOME_ACME_EMAIL` | Email used when dialhome gets its own certificate (optional) |
| `DIALHOME_CONTROL_LISTEN` | When Traefik / nginx already holds 443: the control plane listens on a separate plain-HTTP port, and the proxy in front ends TLS and forwards to it |
| `DIALHOME_PROXY_PROTOCOL` | `=1`: connections on the SNI port must carry a PROXY header (add it in the proxy in front when it passes TLS through); otherwise per-IP rate limits all land on the proxy |

The old `HERDR_RELAY_*` names from before the rename still work (the new one wins when both are set), and the old
`~/.herdr-relay` directory is still used when it exists and the new one doesn't.

## The host side (for other projects)

The host side is a Go package; herdr-web and gerdr both import it directly:

```go
import "github.com/zbysir/dialhome/relay"

relay.Join(ctx, relay.HostConfig{URL: "https://relay.example.com", Host: "mac.example.com", Dir: keyDir}, inviteCode)
tn, _ := relay.Start(relay.HostConfig{...}) // tn is a net.Listener; each Accept gives the TLS byte stream from a phone
```

Treat connections from the tunnel as coming from the **public internet** (the peer address is what the relay says it
is, so use it only for rate limiting), and end TLS yourself.

## Development

```sh
make build   # bundle the frontend + go build → ./dialhome
make test    # go vet + go test + frontend typecheck
make dev     # frontend hot reload (/api goes to 127.0.0.1:7900)
```

Release: `make release V=v0.1.0` pushes a tag; GitHub Actions builds the binaries and the `ghcr.io/zbysir/dialhome` image.

## License

MIT
