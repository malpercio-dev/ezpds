# Bundled brand fonts

These font files are **self-hosted** and bundled into the build so the app renders
its brand type **offline** — a Tauri WKWebView loads from disk with no web server,
and a security/identity wallet must never fetch fonts from a runtime CDN.

`adapter-static` copies `static/` into `dist/`, so these are served at `/fonts/…`.
The `@font-face` declarations live in `src/lib/styles/fonts.css`.

| Family | Role | Weights | File(s) | Source | License |
|---|---|---|---|---|---|
| Public Sans | UI / body (the working voice) | 400, 500, 600, 700 | `PublicSans-*.woff2` | [uswds/public-sans](https://github.com/uswds/public-sans) | OFL 1.1 |
| JetBrains Mono | data — DIDs, keys, CIDs | 400, 500 | `JetBrainsMono-*.woff2` | [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono) | OFL 1.1 |
| Libre Caslon Display | display — the signet (display moments only) | 400 | `LibreCaslonDisplay-Regular.ttf` | [google/fonts](https://github.com/google/fonts/tree/main/ofl/librecaslondisplay) | OFL 1.1 |

All three are Open Font License — free to bundle and redistribute.

To update or re-fetch, pull the same weights from the upstream repos above and keep
the filenames in sync with `src/lib/styles/fonts.css`. Caslon ships as TTF (no
upstream woff2); it can be optimized to woff2 later with `woff2_compress` if size matters.
