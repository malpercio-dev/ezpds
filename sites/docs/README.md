# Documentation site — Obsign & Custos

Two audience-scoped documentation surfaces, built with [Astro Starlight][sl] and
deployed as a single static site with global search:

- **Using Obsign** (`src/content/docs/user/`) — the user surface: onboarding,
  tamper monitoring and the 72-hour recovery override, 2-of-3 Shamir backup,
  identity migration.
- **Running Custos** (`src/content/docs/operator/`) — the operator surface:
  running a relay, the config/env surface, the custody seam, moderation.

This is the *published*, audience-facing documentation. The repository's internal
`docs/` tree (specs, ADRs, design plans) is the raw material these pages are
written from and is deliberately **not** published here. Design plan:
[`docs/design-plans/2026-07-14-documentation-sites.md`](../../docs/design-plans/2026-07-14-documentation-sites.md).

## Two registers, not cross-applied

The two surfaces speak the repo's two scoped design registers — do **not**
cross-apply one to the other (see root `AGENTS.md` → Design Context):

- The default register is **Obsign, "The Sealed Credential"** (root `PRODUCT.md`
  + `DESIGN.md`): archival white, sealing-wax gold + aubergine, Public Sans
  working voice, Libre Caslon Display as the once-per-screen signet (the site
  title), JetBrains Mono for literals. Rendered in light and dark.
- The **operator** surface carries the **Brass Console** register
  (`apps/admin-companion/PRODUCT.md` + `DESIGN.md`): cool-slate dark ground,
  lifted brass accent, monospace-forward headings. Dark by design — the register
  has no light appearance.

`src/styles/theme.css` forks the two live app token layers
(`apps/identity-wallet/src/lib/styles/tokens.css` and
`apps/admin-companion/src/lib/styles/tokens.css`, via the marketing fork in
`sites/marketing/assets/css/site.css`) onto Starlight's CSS-variable scale.
Values must not drift from those files; when a brief changes, re-fork.

The operator register is scoped to `operator/*` routes by
`src/components/PageFrame.astro`, which wraps Starlight's page frame in a
`.register-custos` element for those pages only — so the header, sidebar, and
content all switch register together, and the two never bleed into each other.

Held invariants (from the marketing site): WCAG 2.2 AAA text targets; status
never signalled by color alone (Starlight asides pair icon + title + color);
visible focus ring on every interactive element; `prefers-reduced-motion`
honored; fonts self-hosted in `src/fonts/` (copied from
`apps/identity-wallet/static/fonts/`), no runtime CDN.

## Local development

```sh
pnpm install
pnpm dev        # dev server with hot reload
pnpm build      # static build into dist/ (+ Pagefind search index)
pnpm preview    # serve the built dist/
pnpm check      # astro check (type + content diagnostics)
```

## Serving

Production is a Caddy container (`Dockerfile` + `Caddyfile`) deployed as its own
Railway service — a second service in the PDS's Railway project, scoped to this
directory (`Root Directory = sites/docs`) so it stays independent of the
repo-root `railway.toml`. Unlike the zero-build marketing site, Starlight
compiles to static HTML, so the `Dockerfile` has a Node build stage; the runtime
image is still just Caddy serving `dist/`. The `Caddyfile` handles gzip/zstd,
clean URLs, immutable caching for fingerprinted `/_astro/*` and `/pagefind/*`
assets, and cache/security headers. Full setup — including pointing
`docs.obsign.org` at it — is in [docs/deploy.md](../../docs/deploy.md) →
"Documentation site". To run the container exactly as deployed:

```sh
docker build -t obsign-docs sites/docs
docker run --rm -p 8080:8080 obsign-docs   # http://localhost:8080
```

[sl]: https://starlight.astro.build/
