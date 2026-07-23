# Marketing site — Obsign & Custos

A static, zero-build marketing site: what Obsign and Custos are, what they do,
and the differentiators — cryptographic (not custodial) identity sovereignty,
tamper monitoring with the 72-hour recovery override, 2-of-3 Shamir backup, and
credible exit as a property of the keys.

## Pages

- `index.html` — the Obsign story, user-facing, with a Brass Console band
  introducing Custos.
- `custos/index.html` — the operator story: what Custos runs, how to run it,
  and the custody seam (`rotationKeys[0]` device / `rotationKeys[1]` recovery,
  both user-held / `rotationKeys[2]` server).

## Social cards (Open Graph)

Each page links a 1200×630 `og:image` (`summary_large_image`) so shared links
unfurl as a branded card. The images are generated, not hand-drawn: the HTML
sources (`assets/og/*.src.html`) use the same forked tokens and self-hosted
fonts as the pages — Obsign in the Sealed-Credential register, Custos in the
Brass Console. Regenerate with `assets/og/render.sh` (headless Chrome + the
pure-Node `pngcrop.mjs`; the script documents the 717→630 headless-crop trick).
`og:image` URLs are absolute against `about.obsign.org`.

## Design derivation

The two pages speak the repo's two scoped design registers — do **not**
cross-apply one to the other (see root `AGENTS.md` → Design Context):

- The default register is **Obsign, "The Sealed Credential"** (root
  `PRODUCT.md` + `DESIGN.md`): archival white, sealing-wax gold + aubergine,
  Public Sans working voice, Libre Caslon Display as the once-per-screen
  signet, JetBrains Mono for every literal value.
- `.register-custos` scopes the **Brass Console** register (
  `apps/admin-companion/PRODUCT.md` + `DESIGN.md`): cool slate ground, lifted
  brass accent, monospace-forward prompt as the display voice.

Tokens in `assets/css/site.css` are **forked from the live app token layers**
(`apps/identity-wallet/src/lib/styles/tokens.css` and
`apps/admin-companion/src/lib/styles/tokens.css`). Values must not drift from
those files; when a brief changes, re-fork.

The Obsign register follows the system appearance: each color token is a
`light-dark()` pair forked from the wallet's dark appearance (§2 of root
`DESIGN.md`), and `:root` carries `color-scheme: light dark`. There is no toggle
and no JavaScript — the switch is `prefers-color-scheme` alone, so there is no
flash. The seal gold is appearance-invariant (the Same-Seal Rule) and every dark
text pairing is verified AAA, never eyeballed. The Brass Console (`.register-custos`)
is a **fixed dark register** — it does not follow the system in either place it
appears (the Custos page body and the Custos CTA band on the Obsign page).

Web-scale extension: the app type scales are mobile-restrained, so the site
extends the same ~1.2 modular scale up two fixed-rem steps (`--text-display`
2.1rem, `--text-hero` 2.5rem), stepped down behind a media query — never fluid
`clamp()` (the briefs' fixed-rem doctrine).

Held invariants: WCAG 2.2 AAA targets; status never color alone (color + icon
+ label + position); flat at rest (tonal layers + 1px hairlines, no resting
shadows); visible focus ring on every interactive element (aubergine on light,
gold on dark); matte gold, never metallic; `prefers-reduced-motion` honored;
fonts self-hosted in `assets/fonts/` (copied from
`apps/identity-wallet/static/fonts/`), no runtime CDN; no JavaScript beyond
the one self-hosted, cookieless analytics `<script>` (see "Analytics" below).

## Analytics

Self-hosted, cookieless, IP-anonymized page-view analytics (Umami — see
[ADR-0029](../../docs/architecture/decisions/0029-self-hosted-web-analytics-marketing-only.md)),
present on every page of this site only (`index.html`, `custos/index.html`,
`privacy.html`). It is a Railway service run alongside the PDS's other
services. `privacy.html` discloses what it collects and doesn't; the footer
on every page links it. Per the ADR, analytics never extends to the docs
site, either mobile app, the PDS backend, or any auth/PII surface.

Umami's own website-level "Domain" setting is cosmetic only (it filters
self-referrals out of the referrer list; it does not gate the collection
API), so the embed carries `data-domains="about.obsign.org"` — Umami's
client-side hostname allowlist — to keep this site's non-production
deployments (Railway staging, local previews) from reporting into the
production dashboard.

## Serving

Any static file host — the site is plain HTML/CSS/fonts with no build step.

Quick local preview:

```sh
python3 -m http.server -d sites/marketing 8000
```

Production is a Caddy container (`Dockerfile` + `Caddyfile`) deployed as its own
Railway service — a second service in the PDS's Railway project, scoped to this
directory (`Root Directory = sites/marketing`) so it stays independent of the
repo-root `railway.toml`. The `Caddyfile` handles gzip/zstd, clean URLs, and
cache/security headers. Full setup — including pointing `about.obsign.org` at
it — is in [docs/deploy.md](../../docs/deploy.md) → "Marketing Site". To run the
container exactly as deployed:

```sh
docker build -t obsign-marketing sites/marketing
docker run --rm -p 8080:8080 obsign-marketing   # http://localhost:8080
```
