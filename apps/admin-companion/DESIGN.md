---
name: Admin Companion
description: A precision operator console for an ezpds relay — brass on cool steel, dark-first, monospace-forward.
# Tokens are OKLCH-canonical (forked from the Obsign architecture). Some sit outside the
# sRGB gamut by design, so Stitch's hex linter will warn — that is expected. The live source
# of truth is src/lib/styles/tokens.css; tonal ramps, shadows, motion, and full component
# HTML/CSS snippets live in the .impeccable/design.json sidecar.
colors:
  primary: "oklch(0.72 0.12 80)"
  primary-hover: "oklch(0.78 0.13 82)"
  primary-deep: "oklch(0.70 0.13 78)"
  on-primary: "oklch(0.16 0.012 250)"
  on-color: "oklch(0.96 0.006 250)"
  bg: "oklch(0.18 0.012 250)"
  surface: "oklch(0.22 0.014 250)"
  surface-raised: "oklch(0.26 0.015 250)"
  line: "oklch(0.34 0.012 250)"
  border-strong: "oklch(0.52 0.012 250)"
  ink: "oklch(0.95 0.006 250)"
  ink-soft: "oklch(0.82 0.008 250)"
  muted: "oklch(0.73 0.010 250)"
  safe: "oklch(0.82 0.10 150)"
  safe-surface: "oklch(0.26 0.04 150)"
  warning: "oklch(0.82 0.10 50)"
  warning-surface: "oklch(0.26 0.04 50)"
  critical: "oklch(0.82 0.10 25)"
  critical-surface: "oklch(0.26 0.04 25)"
  critical-solid: "oklch(0.44 0.16 25)"
  info: "oklch(0.82 0.10 240)"
  info-surface: "oklch(0.26 0.04 240)"
typography:
  display:
    fontFamily: "JetBrains Mono, ui-monospace, 'SF Mono', Menlo, monospace"
    fontSize: "1.625rem"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "0.02em"
  headline:
    fontFamily: "system-ui, -apple-system, 'Helvetica Neue', sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "normal"
  title:
    fontFamily: "system-ui, -apple-system, 'Helvetica Neue', sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: "normal"
  body:
    fontFamily: "system-ui, -apple-system, 'Helvetica Neue', sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "normal"
  label:
    fontFamily: "system-ui, -apple-system, 'Helvetica Neue', sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "0.01em"
  data:
    fontFamily: "JetBrains Mono, ui-monospace, 'SF Mono', Menlo, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "normal"
rounded:
  sm: "4px"
  md: "6px"
  lg: "10px"
  xl: "14px"
  full: "9999px"
spacing:
  "2xs": "2px"
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  "2xl": "48px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-primary-active:
    backgroundColor: "{colors.primary-deep}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
    height: "44px"
  button-destructive:
    backgroundColor: "{colors.critical-solid}"
    textColor: "{colors.on-color}"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
    height: "44px"
  status-chip:
    backgroundColor: "{colors.safe-surface}"
    textColor: "{colors.safe}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "4px 8px"
  code-surface:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
  text-field:
    backgroundColor: "{colors.surface-raised}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    rounded: "{rounded.md}"
    padding: "8px 16px"
    height: "44px"
  toggle-track-on:
    backgroundColor: "{colors.primary}"
    rounded: "{rounded.full}"
    width: "40px"
    height: "24px"
---

# Design System: Admin Companion

## 1. Overview

**Creative North Star: "The Brass Console"**

This is the control surface of a precision instrument: brass dials and gold indicator lamps lit against cool brushed steel, in a calm, dimly-lit operations room. The operator who self-hosts a relay administers it today from a terminal; this is that terminal made into an instrument they can hold — exact, dense, and fast, the way good operator tooling (Warp, Charm, Linear, Railway) is exact. Gravitas comes from precision and legible density — aligned columns, monospace where the data is literal, gold reserved for the one action that matters — never from chrome and never from theatrics.

It is the **technical sibling of Obsign**, the identity wallet. It shares Obsign's soul — the sealing-wax gold, the "practice the assurance you preach" rigor, the WCAG 2.2 AAA bar — but deliberately inverts the register: where Obsign is warm parchment under daylight, this is cool slate under low light; where Obsign hides the cryptographic machinery behind plain human stakes, this leads with it, because the machinery is the operator's native language. The two apps are recognizably the same house; this one is the operator's room in it.

This system explicitly rejects **hacker cosplay / terminal kitsch** (CRT scanlines, phosphor glow, Matrix rain, `h4ck3r` green-on-black, fake boot logs as decor), **consumer-app friendliness** (humane onboarding carousels, soft playful cards, mascots, reassurance copy — Obsign's lane, not this one), **crypto / web3 hype** (neon, coins, gradients), the **enterprise dashboard / chart-soup** (gauge clusters, KPI hero cards), and the **low-contrast dark-theme cliché** (gray-on-darker-gray mush). Terminal-native here means a *refined* command surface, not a costume.

**Key Characteristics:**
- Cool slate ground, sealing-wax gold accent — brass on steel, a deliberate temperature/value inversion of Obsign's gold-on-white.
- Monospace-forward: the mono is the signature voice (the literal truth of a code or key), a grotesk carries dense UI and prose.
- Dense but legible — the clarity of a good `ls -l`, never chart-soup, never mush.
- Gold is the one action, never decoration; status is the green/amber/red/slate ramp, never gold.
- Status is never color alone — color + glyph + text + position, always.
- WCAG 2.2 AAA, held against a dark ground where it is hardest — the one Obsign principle carried with zero compromise.

## 2. Colors

A cool-slate dark foundation (a temperature inversion of Obsign's warm paper) carrying a single warm accent — sealing-wax gold, brought over from Obsign — plus a disciplined status ramp reserved entirely for security/operational state. Strategy: **Restrained** (dark neutrals + one accent ≤10% of any screen). Values are OKLCH starting anchors; exact ramps finalize on the scan-mode re-run.

### Primary
- **Sealing-Wax Gold** (`oklch(0.72 0.12 80)`): the accent, carried from Obsign and lifted for legibility on the dark ground. Primary actions, the active/selected state, the focus ring, the brand mark. Used as a fill with deep-slate text, or as a gold icon/label on slate for the current item. Pressed **Deep Brass** (`oklch(0.70 0.13 78)`); hover **Lit Brass** (`oklch(0.78 0.13 82)`). Matte and dry — brass, never bright leaf-gold or metallic glint.

### Neutral — cool steel & light
- **Console Slate** (`oklch(0.18 0.012 250)`): the ground. A cool blue-tinted near-black; the deepest surface. The brass and the type carry the warmth, the ground stays cool.
- **Panel Slate** (`oklch(0.22 0.014 250)`): cards, panels, the primary raised surface.
- **Raised Slate** (`oklch(0.26 0.015 250)`): nested panels, input wells, hover rows.
- **Steel Line** (`oklch(0.34 0.012 250)`): 1px hairline borders and dividers — never a colored stripe.
- **Filament** (`oklch(0.95 0.006 250)`): primary text and headings — a cool near-white (high contrast on Console Slate, comfortably AAA).
- **Filament Soft** (`oklch(0.82 0.008 250)`): secondary prose that must still clear AAA.
- **Filament Dim** (`oklch(0.73 0.010 250)`): labels and metadata; body copy uses Filament, not this.

### Status (security / operational signal only)
Each state is a **tonal pair**: a lifted signal tone (icon/text) over a deep same-hue surface ground — the dark-ground inversion of Obsign's pale-ground badges. Hues are chosen to sit clear of the brass accent.
- **Verified Green** — `oklch(0.82 0.10 150)` on surface `oklch(0.26 0.04 150)`: a device/request authorized; live and good.
- **Caution Amber** — `oklch(0.82 0.10 50)` on surface `oklch(0.26 0.04 50)`: attention needed. Pushed orange (hue 50) to stay clear of the brass accent (hue 80).
- **Alarm Red** — `oklch(0.82 0.10 25)` on surface `oklch(0.26 0.04 25)`; solid fill **Alarm Solid** (`oklch(0.44 0.16 25)`) with light text for a destructive confirm.
- **Calm Slate** — `oklch(0.82 0.10 240)` on surface `oklch(0.26 0.04 240)`: neutral information.

### Named Rules
**The Seal-vs-Signal Rule** *(carried from Obsign).** Gold is *action and identity*; the green/amber/red/slate ramp is *status*. Status colors always carry a glyph and a text label and appear only in status contexts. Gold never masquerades as a status, and a status color never carries the brand. This rule is what lets a warm accent and a warm-ish amber coexist without confusion.

**The Cool-Ground Rule.** The surface stays cool slate (hue ~250). Warmth lives in the brass accent and nowhere else. Tinting the ground warm "to feel inviting" is forbidden — this is an instrument, not a hearth, and it muddies AAA contrast.

**The One-Lamp Rule.** Brass appears on ≤10% of any screen — ideally one element: the primary action or the current selection. A console with every control lit gold is a console no operator can read. Its rarity is what makes it read as *the* action.

## 3. Typography

**Display / Data Font (mono):** [mono to be finalized at implementation — carrying **JetBrains Mono** from Obsign for cross-app data continuity is the default; it is not a reflex-reject face]
**UI / Body Font (grotesk):** [a technical grotesk to be chosen at implementation — explicitly avoid the reflex-reject defaults: Inter, Space Grotesk, IBM Plex, DM Sans]

**Character:** A two-face system that inverts Obsign's. Where Obsign's ceremonial face is an engraved serif (the signet) and its working voice is a humanist sans, here the **monospace is the signature voice** — the prompt, the wordmark, every literal value — and a clean **technical grotesk** carries dense UI and prose. Mono is elevated, not relegated: it's the operator's register, the sound of exact output. Fixed-rem modular scale (~1.2 ratio), never fluid `clamp()`. Light-on-dark reads lighter, so line-heights run a touch looser than Obsign's.

### Hierarchy
- **Display** (mono, ~1.625rem, 1.2): the wordmark and screen header — the "prompt." Mono is the signet here. At most once per screen.
- **Headline** (grotesk, 600, ~1.375rem, 1.25): section and screen headings — the working voice.
- **Title** (grotesk, 600, ~1.125rem, 1.35): card titles, group headers, a device label.
- **Body** (grotesk, 400, 1rem, 1.6): prose and explanations. Cap prose at 65–75ch; dense rows may run wider.
- **Label** (grotesk, 500, 0.8125rem, +0.01em): buttons, field labels, metadata. Sentence case.
- **Data** (mono, 0.875rem, 1.55): claim codes, `did:key`s, device IDs, timestamps, status values — anything literal and verifiable. Wraps `break-all`; never truncates a code silently.

### Named Rules
**The Literal-Truth Rule** *(carried from Obsign).** Every code, `did:key`, device ID, and signature is set in mono. Monospace signals "this is exact, verify it character by character." Proportional type is for prose, never for literals.

**The Mono-as-Voice, Not-Costume Rule.** Mono is elevated because this audience *is* technical and reads literal output — not as a decorative "developer" skin. The instant mono is paired with scanlines, glow, or fake terminal chrome, it has become the kitsch this system bans. Refined command surface, never costume.

## 4. Elevation

Flat by default; motion and depth are Restrained. Depth is built from **tonal layers** (Console Slate → Panel Slate → Raised Slate) and **1px Steel Line hairlines**, not from drop shadows — on a dark ground, shadows mostly vanish anyway, so a lighter tonal step and a hairline do the work. A resting panel is Panel Slate with a hairline; no shadow.

Elevation appears only when an element genuinely floats and must read as *temporary and modal*: a confirmation sheet, a toast. On dark, that's a faint lift in surface lightness plus a hairline and a soft, neutral, never-colored shadow.

### Shadow Vocabulary
- **Sheet** (`box-shadow: 0 -8px 32px oklch(0.10 0.01 250 / 0.5)`): a confirmation sheet rising from the bottom.
- **Toast** (`box-shadow: 0 4px 20px oklch(0.10 0.01 250 / 0.5)`): transient status notifications.

### Named Rules
**The Flat-At-Rest Rule** *(carried from Obsign).** Surfaces are flat with a hairline at rest. A shadow is a response to *floating* (sheet, toast) — a state, not a decoration. A panel with a resting shadow is wrong.

## 5. Components

The canonical primitives live in `src/lib/components/ui/` as Svelte 5 components and
compose the tokens in `src/lib/styles/tokens.css` (control radius `--control-radius`,
touch floor `--control-min-height: 44px`, focus ring `--ring-width`). They are exercised
in every state at the `/preview` route. No hardcoded hex/px — every value is a `var(--*)`.

- **`Button`** — precise tight radius (`--control-radius`, 6px, tighter than stock-iOS), 44px min height. `primary` is a Sealing-Wax Gold fill with deep-slate ink (the One-Lamp action, at most once per screen); `secondary` is Panel Slate with a Steel Line hairline (the quiet default); `destructive` is Alarm Solid with light text, reserved for the irreversible revoke/unpair. Full state set: default / hover / active / disabled / `loading` (an inline spinner, held still under reduced motion).
- **`CodeOutput`** *(signature component)* — a claim code, `did:key`, or device ID as copyable terminal output: mono on Raised Slate, optional leading `▸` prompt glyph, a copy affordance that confirms with a check + the word "copied" + the safe tone (never color alone) and announces to VoiceOver via `aria-live`. Wraps `break-all`; **never truncates a literal silently** (Literal-Truth rule). The demo-lifesaver surface.
- **`DeviceRow`** — a dense, aligned `ls -l` row: label + shortened mono `did:key` (head…tail with a **visible** ellipsis — explicit, not silent — the full value one tap away) + last-seen, with a `StatusChip` on the right. The operator's current device is marked by a gold "this device" label, **not** a side-stripe. Renders as a real `<button>` when tappable, a `<div>` otherwise (no dynamic-element a11y ambiguity).
- **`StatusChip`** — the tonal-pair badge: signal tone on a deep same-hue surface, a terminal glyph (`●` active/ready · `◌` pending · `⊘` revoked · `!` error · `○` info), **and** a text label. The glyph is `aria-hidden`; the label is the screen-reader truth. Color + glyph + text + position — never color alone.
- **`TextField`** — Raised Slate well, Steel Line (`--color-border-strong`) border, 2px gold focus ring; `mono` variant for fields that take a literal value (relay URL, pairing code). Error state is a red border + a leading `!` glyph + a message, never color alone.
- **`ScreenShell`** — the screen scaffold: the `ezpds ▸ <prompt>` line (mono, the one display moment per screen) over a working-voice headline, an optional back affordance, the body, and an optional pinned actions row. Keeps every operator screen structurally identical.
- **Focus-visible** — a 2px gold ring with offset on every interactive element (global, in `base.css`); never removed (visible focus is a security feature here).

Every text-on-surface and text-on-color pairing these compose is verified WCAG 2.2 AAA
(see the contrast note in `tokens.css`). These primitives are assembled into the operator
screens — Pair, Home, Settings, and the error/recovery states. The machine-readable token
layer lives in this file's frontmatter and the `.impeccable/design.json` sidecar (tonal
ramps, shadows, motion, and the full component HTML/CSS the live panel renders).

## 6. Brand Mark & App Icon

**The mark is the operator's prompt: `❯ _`** — a sealing-wax-gold shell chevron and a
filament underscore cursor on the Console Slate ground. It is the app's own signature
glyph promoted to brand: the `ezpds ▸` prompt line every screen leads with, waiting for
input. Gold carries the prompt (the One Lamp — the brand mark is the accent's one
sanctioned identity role per the Seal-vs-Signal rule); the cursor is cool filament, the
machine's voice, not a second lamp. The chevron is an *open stroke* and the cursor an
underscore deliberately: a filled `▸` beside a full-height bar reads as a media
skip-track button at icon size.

- **Files:** [`app-icon.svg`](app-icon.svg) (vector source of truth, geometry and color
  documented inline) → `app-icon.png` (the 1024×1024 render `cargo tauri icon`
  consumes). `just admin-postinit` (Patch G) regenerates the iOS asset catalog from it
  after every `cargo tauri ios init`; `just admin-check` verifies via a sha256 marker.
- **iOS 26 fit:** drawn full-bleed on the square with no baked-in corner radius, gloss,
  or edge shadow — the system applies the squircle mask and Liquid Glass material. The
  SVG's two groups (`layer-background` / `layer-glyph`) are Icon Composer seams if the
  mark is ever rebuilt as a layered `.icon` file. Depth is a shallow vertical gradient
  and one soft lift shadow, matte per the no-metallic-glint rule.
- **Anti-reference check:** no scanlines/phosphor/fake chrome (kitsch), no coin or
  glint (crypto), no filled play/skip triangle (media), dark ground held at the same
  cool hue 250 as the app itself.
- **Sibling relationship:** the deliberate inverse of Obsign's icon (the wax seal,
  root DESIGN.md §6) — same gold family, cool console slate vs. archival white, the
  operator's prompt vs. the sealed credential. One house, two rooms.

## 7. Do's and Don'ts

### Do:
- **Do** keep the ground cool slate (`oklch(0.18 0.012 250)`) and let brass and type carry the warmth.
- **Do** treat gold as the One Lamp — the single primary action or current selection, ≤10% of the screen. Matte brass, never metallic glint.
- **Do** hold WCAG 2.2 AAA against the dark ground — Filament on Console Slate clears it; verify every text-on-color and every status pairing.
- **Do** signal status with color **and** a glyph **and** a text label **and** position — always all four (`● active` / `⊘ revoked` / `! error`).
- **Do** set every claim code, `did:key`, device ID, and signature in mono; wrap `break-all`, never truncate a literal silently.
- **Do** lead with the literal — report exact output the way a terminal would, not soft consumer phrasing.
- **Do** keep density legible: aligned columns, the clarity of a good `ls -l`.
- **Do** keep a visible 2px gold focus ring on every interactive element.
- **Do** stay flat at rest; reserve the two soft shadows for floating sheets and toasts.

### Don't:
- **Don't** do **hacker cosplay / terminal kitsch** — no CRT scanlines, phosphor glow, Matrix rain, `h4ck3r` green-on-black, or fake boot logs as decoration. Refined command surface, not costume.
- **Don't** drift into **consumer-app friendliness** (Obsign's lane): no humane onboarding carousels, soft playful cards, mascots, emoji-led empty states, or reassurance copy.
- **Don't** ship the **low-contrast dark-theme cliché**: no gray-on-darker-gray mush. If body text is even close to 7:1, push it toward Filament.
- **Don't** let gold look like money — no metallic gradients, coin shapes, or glint. The instant it reads as currency it's the **crypto/web3** anti-reference.
- **Don't** build the **enterprise dashboard / chart-soup**: no gauge clusters, KPI hero cards, or SaaS analytics widgets. Density is legible operator *output*, not dashboards.
- **Don't** let a status color carry the brand, or gold masquerade as a status (the Seal-vs-Signal Rule).
- **Don't** signal urgency by color alone — a colorblind operator must never have to guess which device is live.
- **Don't** use a `border-left`/`border-right` colored stripe; use a full 1px Steel Line hairline, a tonal ground, or a leading glyph.
- **Don't** use gradient-clipped text, decorative glassmorphism, or a big-number hero-metric template.
