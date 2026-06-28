# Bundled fonts

Self-hosted so the Tauri WKWebView (which loads from disk, with no web server) never
fetches a font from a runtime CDN — a hard rule for a security tool.

| File | Family | Role | License | Source |
|---|---|---|---|---|
| `JetBrainsMono-Regular.woff2` | JetBrains Mono | the literal truth — codes, did:keys, IDs | OFL 1.1 | https://github.com/JetBrains/JetBrainsMono |
| `JetBrainsMono-Medium.woff2`  | JetBrains Mono | mono emphasis | OFL 1.1 | https://github.com/JetBrains/JetBrainsMono |

JetBrains Mono is the **signature voice** of the Brass Console (see `DESIGN.md` §3),
carried from Obsign for cross-app data continuity.

The UI/prose **grotesk** is currently the system technical grotesk (SF Pro on iOS) via
the `--font-sans` token stack — no file is bundled for it yet. A bespoke grotesk is
chosen on the `/impeccable` font-finalization pass; `DESIGN.md` rules out Inter, Space
Grotesk, IBM Plex, and DM Sans. When one is chosen, add its `@font-face` to
`src/lib/styles/fonts.css` and its files here.
