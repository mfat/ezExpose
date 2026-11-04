# Roadmap

ezExpose will become a product: a tool that puts apps you already run behind real HTTPS,
privately over Tailscale or publicly with your own domain. The core comes first and has
to be fully stable before any work on the user experience or a UI.

The rule behind every step: a broken, interrupted or repeated operation must never
expose, overwrite or delete something ezExpose doesn't own.

## 1. Safety fixes in the packages (done)

- Tailscale's `Serve` and `Close` leave any route that isn't ours alone.
- Every Caddy field is checked before it reaches the config, and CI runs the output
  through the pinned Caddy.
- Setup tokens need at least 16 characters.
- Cloudflare records carry an install ID, so two installs can't change each other's.
- `PublicIP` checks its answer, and `IsPublic` no longer counts reserved addresses.
- Downloads resume only from the right byte and give up eventually. A damaged cached
  `lego` is fetched again.
- A token file other users can read is refused.
- CI runs the race detector.

## 2. State and recovery (done)

A state file that records what ezExpose owns: each exposure, its Tailscale route, DNS
record ID, certificate and Caddy site. Every change follows plan, apply, verify, then
save. If it's interrupted, running it again finishes it or undoes it. When it's unclear
whether something is ours, the answer is to refuse.

Tests crash at every change, before and after it takes effect, for every kind of access.

## 3. A headless CLI, private access first (done)

`doctor`, `plan`, `apply`, `status`, `remove` and `reconcile`, with versioned JSON output
and clear errors. The first route is Tailscale. It's done when the whole lifecycle passes
twice on a clean Linux host, a second run changes nothing, someone else's route survives,
and a killed run recovers.

Proven on a real server on 2026-11-04: opened from another device with a trusted
certificate, a second apply changed nothing, another app's route on 443 survived, and
apply and remove killed at six points each always recovered. Tailscale's settings ended
byte-for-byte as they began. The server wasn't clean: it already ran ezVaultwarden, which
made a good test of leaving other routes alone.

## 4. Public access and renewal (done)

Caddy on port 443, Cloudflare DNS and certificates, with renewal that runs on the server
on its own schedule. It's done when a public exposure works end to end, renews after a
restart, and a failure neither breaks anything else nor reports success.

Proven on the same server on 2026-11-04:

- Public access got a real certificate over port 443 alone, as root and as a normal user,
  beside Tailscale holding 443 on its own address. With `--cloudflare` it also made the DNS
  record, and removing it deleted the record.
- LAN access on the server's Tailscale address got a real certificate through Cloudflare
  and was opened by name from another device. Your router may still hide the name; see
  the README.
- `renew` did nothing when nothing was due. `renew --force` got a new certificate and Caddy
  served it at once. The timer's service runs cleanly.
- systemd restarted a killed Caddy, and removal stopped it and deleted its units.

## Before the UI

Done on 2026-11-04:

- `plan --out` and `apply --plan-file`: a plan is applied only if working it out again
  gives the same result, so a UI can't approve one thing and get another.
- With `--json`, one object per line: progress events, then the result.
- `version --json` reports ezExpose's version, commands, features and pinned tools, and
  whether Tailscale is new enough. Tailscale before 1.52 is refused.
- Fuzz tests for the Caddy input checks, the address checks, download ranges, the record
  file and version comparison. Run them with limits, as below.
- IPv6-only machines get AAAA records and the right advice. Public access behind
  carrier-grade NAT is refused up front, and a certificate that never arrives explains
  port forwarding.

A second code review on 2026-11-04 found ten problems. All are fixed, each with a test:

- Two apps could share a name, and removing one took the other's DNS record and
  certificate. Each public or LAN name now belongs to one app.
- Removal ignored a failed service stop. Units are now kept until confirmed stopped.
- A crash during the record's backup step blocked every later save.
- Moving between IPv4 and IPv6 deleted the old DNS record before the new one existed.
- A lost reply from Cloudflare left a record ezExpose had made but no longer tracked.
- A site whose certificate never came stayed served by Caddy. It's now taken back out.
- The Cloudflare client read a token file other users could read, or a link.
- An approved plan was checked and applied under separate locks.
- JSON runs could end with two results, usage errors weren't JSON, reconcile hid
  problems, and --json could still stop to ask a question.

Then the first part of a discovery proposal, kept small on purpose: `ezexpose audit`
lists what ezExpose set up, every Tailscale route with Funnel marked public, what's
listening and which program or Docker container it is. It warns when an app ezExpose
fronts can also be opened directly without HTTPS, and names the program holding port 443.
On the real server, a fingerprint of Tailscale's settings, the service files and the
listening ports was identical before and after every audit.

Left for later, until someone needs them: reading Nginx, Caddy and Traefik configs,
taking over existing certificates, migration, and DNS or TLS probes during an audit.

Still to do:

- A reboot test and a second Linux distribution, on a spare machine.
- An install script and a first release.

Fuzzing uses every core and a lot of memory by default, and once froze a desktop. Run
one target at a time, limited:

```bash
systemd-run --user --scope -p MemoryMax=3G -p CPUQuota=200% nice -n 19 \
  go test ./caddy -run '^$' -fuzz FuzzRenderCanOnlyFillFields -fuzztime 20s -parallel 2
```

## 5. Then the user experience and UI

A desktop app (and later SSH Pilot and mobile) that runs the same CLI over SSH. Nothing
in the UI does anything the CLI doesn't.

## Not planned yet

Installing apps for the user, Docker management, and a web dashboard.
