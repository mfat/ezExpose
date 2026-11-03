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

## 2. State and recovery

A state file that records what ezExpose owns: each exposure, its Tailscale route, DNS
record ID, certificate and Caddy site. Every change follows plan, apply, verify, then
save. If it's interrupted, running it again finishes it or undoes it. When it's unclear
whether something is ours, the answer is to refuse.

## 3. A headless CLI, private access first

`doctor`, `plan`, `apply`, `status`, `remove` and `reconcile`, with versioned JSON output
and clear errors. The first route is Tailscale. It's done when the whole lifecycle passes
twice on a clean Linux host, a second run changes nothing, someone else's route survives,
and a killed run recovers.

## 4. Public access and renewal

Caddy on port 443, Cloudflare DNS and certificates, with renewal that runs on the server
on its own schedule. It's done when a public exposure works end to end, renews after a
restart, and a failure neither breaks anything else nor reports success.

## 5. Then the user experience and UI

A desktop app (and later SSH Pilot and mobile) that runs the same CLI over SSH. Nothing
in the UI does anything the CLI doesn't.

## Not planned yet

Installing apps for the user, Docker management, and a web dashboard.
