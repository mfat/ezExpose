# ezExpose

Put apps you already run behind real HTTPS, without opening your machine to the internet
unless you choose to. It grew out of
[ezVaultwarden](https://github.com/mfat/ezVaultwarden).

> **Early development.** The core is being made stable before any UI. The
> [roadmap](docs/roadmap.md) says what's done and what's next.

```text
$ ezexpose apply --backend 127.0.0.1:8080 --access private
Address: https://box.tail1.ts.net
  1. Check that 127.0.0.1:8080 answers
  2. Forward https://box.tail1.ts.net to http://127.0.0.1:8080 over Tailscale, for your own devices only
Continue? [Y/n]
✓ https://box.tail1.ts.net now reaches 127.0.0.1:8080  (exp_0a2afc9f)
  Only your own devices on Tailscale can open it.
```

## Three ways in

| Access | Who can open it | What it needs |
|---|---|---|
| `private` | Your own devices, over Tailscale | Tailscale with MagicDNS and HTTPS turned on |
| `public` | Anyone on the internet | Your own domain pointing here, and port 443 |
| `lan` | Devices on your home network, or with `--address`, your tailnet | Your domain on Cloudflare, and a Cloudflare token |

Public access means anyone can reach the app. HTTPS encrypts the connection but isn't a
login, so ezExpose asks you to confirm the app has its own.

## Commands

| Command | What it does |
|---|---|
| `doctor` | Check this machine is ready for each kind of access |
| `plan` | Show what `apply` would do, changing nothing |
| `apply` | Expose an app, or check and repair one already exposed |
| `status [ID]` | Show what's exposed, as last recorded |
| `remove ID` | Take an exposure down |
| `reconcile` | Check everything against the machine, and finish interrupted work |
| `renew [--force]` | Renew LAN certificates that are due. A timer runs it twice a day |
| `cloudflare-token` | Save a Cloudflare token, readable only by you |
| `logs` | Show Caddy's and renewal's recent output |

Add `--json` to any command for one JSON object on stdout, with `schema`, `ok` and, on
failure, an `error` with a `code` such as `not_ours`, `backend_down` or `port`. Progress goes
to stderr. Exit codes are 0 for done, 1 for failed and 2 for used wrongly.

## What it promises

- **It never changes what it didn't create.** A Tailscale route, DNS record or Caddy you
  set up yourself is left alone, and the error says so.
- **An interruption is always recoverable.** Each change is saved as pending before it's
  made. After a crash, `reconcile` or running the same command again finishes or undoes it.
- **"Removed" means checked.** An exposure leaves the record only once every part is
  confirmed gone.
- **It keeps running without you.** Caddy and renewal are systemd services: user services,
  or system ones when run as root.

The record lives in `~/.local/state/ezexpose`, or `/var/lib/ezexpose` for root.

## Install

There's no release yet. To build it:

```bash
go install github.com/mfat/ezExpose/cmd/ezexpose@latest
```

## Requirements

- Linux with systemd, on 64-bit Intel/AMD or ARM. It's been used on Ubuntu 24.04 and WSL.
- `private`: Tailscale installed and signed in, with MagicDNS and HTTPS turned on in the
  admin console. Without root, run `sudo tailscale set --operator=$USER` once.
- `public`: port 443. Without root, `doctor` shows the one setting that allows it.
- `lan`: a Cloudflare token with Zone:Read and DNS:Edit.
- Go 1.27.3 or later to build it.

## Status

| Route | Tested for real |
|---|---|
| Private, over Tailscale | Yes: opened from another device, run twice, killed mid-way and recovered, beside another app's route |
| Public, Caddy on port 443 | Yes: a real certificate as root and as a normal user, beside Tailscale on the same port |
| Public, with Cloudflare making the record | Yes: record created, certificate in 18 seconds, record gone after removal |
| LAN, with Cloudflare | Yes, on a server's Tailscale address: real certificate, opened by name from another device |
| Certificate renewal | Yes: a forced LAN renewal, with Caddy serving the new certificate at once. Caddy renews public ones itself |

## The packages

The command is built on packages other Go programs can use too.

| Package | Job |
|---|---|
| `tailscale` | Serve a local port to your own devices, never replacing someone else's route |
| `caddy` | Render a Caddyfile for one or more sites on port 443, with port 80 closed |
| `acme` | Get certificates over the DNS challenge with `lego`, so no ports need to be open |
| `cloudflare` | Keep one DNS record pointing at a machine. It only changes records this install created |
| `netcheck` | Check port 443, whether every DNS answer points here, and the public address |
| `fetch` | Verified, resumable downloads of the pinned Caddy and `lego` |

`caddy.Site` can also keep an app's signup closed to strangers: set `SetupToken` and
`SetupPaths`, and those paths answer 403 unless the browser came through `/?setup=TOKEN`.
Clear the token once the first account exists.

## Good to know

Public DNS answers holding a private address get blocked by many routers, such as
OpenWrt's rebind protection, so the LAN route can fail with a correct record. Tailscale's
100.x addresses count as private too. The fix is an exception for your domain on the router.

Cloudflare's token page doesn't always keep the permissions a link fills in, so ezExpose
also gives the steps to make the token by hand.
