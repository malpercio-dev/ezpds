# Marketing site — Obsign & Custos

A static, zero-build marketing site: what Obsign and Custos are, what they do,
and the differentiators — cryptographic (not custodial) identity sovereignty,
tamper monitoring with the 72-hour recovery override, 2-of-3 Shamir backup, and
credible exit as a property of the keys.

## Pages

- `index.html` — the Obsign story, user-facing, with a Brass Console band
  introducing Custos.
- `custos/index.html` — the operator story: what Custos runs, how to run it,
  and the custody seam (`rotationKeys[0]` user / `rotationKeys[1]` server).

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

Web-scale extension: the app type scales are mobile-restrained, so the site
extends the same ~1.2 modular scale up two fixed-rem steps (`--text-display`
2.1rem, `--text-hero` 2.5rem), stepped down behind a media query — never fluid
`clamp()` (the briefs' fixed-rem doctrine).

Held invariants: WCAG 2.2 AAA targets; status never color alone (color + icon
+ label + position); flat at rest (tonal layers + 1px hairlines, no resting
shadows); visible focus ring on every interactive element (aubergine on light,
gold on dark); matte gold, never metallic; `prefers-reduced-motion` honored;
fonts self-hosted in `assets/fonts/` (copied from
`apps/identity-wallet/static/fonts/`), no runtime CDN; no JavaScript.

## Serving

Any static file host. Locally:

```sh
python3 -m http.server -d sites/marketing 8000
```
