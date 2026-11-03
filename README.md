# ezExpose

Go packages that put self-hosted apps behind real HTTPS, without opening your machine
to the internet unless you choose to. Extracted from
[ezVaultwarden](https://github.com/mfat/ezVaultwarden).

This is a library for now. There's no command to run yet.

| Package | Job |
|---|---|
| `tailscale` | Serve a local port to your own devices, with a real certificate |
| `caddy` | Render a Caddyfile for one or more sites on port 443, with port 80 closed |
| `acme` | Get certificates over the DNS challenge with `lego`, so no ports need to be open |
| `cloudflare` | Keep one DNS record pointing at a machine. It only changes records it created |
| `netcheck` | Check port 443, whether every DNS answer points here, and whether the machine is reachable |
| `fetch` | Verified, resumable downloads, and the pinned `lego` |

## Requirements

- Go 1.27.3 or later.
- `tailscale` needs the Tailscale command installed and signed in, with MagicDNS and HTTPS
  turned on in the admin console. Without root, run `sudo tailscale set --operator=$USER` once.
- `acme` runs `lego`. `fetch` pins the Linux builds for 64-bit Intel/AMD and ARM.
- `caddy` only writes the config. Your tool runs Caddy itself.
- The port 443 fix that `netcheck` suggests is for Linux. The packages have only been used
  on Linux, on Ubuntu 24.04 and WSL.

## Status

| Route | Tested for real in ezVaultwarden |
|---|---|
| Tailscale | Yes, reached from a phone |
| Public, Caddy on port 443 | Yes, a real certificate and the first account on a server |
| DNS challenge with Cloudflare | The certificate and DNS record worked. Another device connecting by name, and a real renewal, are unproven |

This repo's own tests use stand-ins, and these packages haven't been run together here.

## First accounts on a public app

Set `SetupToken` and `SetupPaths` on a `caddy.Site`, and those paths answer 403 unless the
browser came through `/?setup=TOKEN`. Strangers can't claim the app first, and an interrupted
setup stays closed. Clear the token once the first account exists.

## Leaving Tailscale

Tailscale forwards straight to the app, past Caddy, so call `tailscale.CLI.Close` before
changing anything else, and don't report access as closed unless it succeeds.

## Before you expose anything

An app with no login of its own is open to anyone who reaches it. A tool built on these
packages has to check that, because they can't.

Public DNS answers holding a private address get blocked by many routers, such as
OpenWrt's rebind protection, so the LAN route can fail with a correct record.
