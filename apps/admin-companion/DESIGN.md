<!-- SEED: re-run /impeccable document (scan mode) once the Tauri app has code, to extract the real tokens, finalize fonts, and generate the .impeccable/design.json sidecar. Component tokens and exact ramps below are starting points, not final. -->
---
name: Admin Companion
description: A precision operator console for an ezpds relay — brass on cool steel, dark-first, monospace-forward.
# Colors are OKLCH-canonical (forked from the Obsign token architecture). Exact ramps and
# component tokens land on the scan-mode re-run once there's code. Seed frontmatter is name +
# description only by design; the anchor values live in the Colors section below.
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
- **Sealing-Wax Gold** (`oklch(0.66 0.12 80)`): the accent, carried from Obsign and lifted for legibility on the dark ground. Primary actions, the active/selected state, the focus ring, the brand mark. Used as a fill with deep-slate text, or as a gold icon/label on slate for the current item. Pressed **Deep Brass** (`oklch(0.56 0.11 78)`); hover **Lit Brass** (`oklch(0.72 0.13 82)`). Matte and dry — brass, never bright leaf-gold or metallic glint.

### Neutral — cool steel & light
- **Console Slate** (`oklch(0.18 0.012 250)`): the ground. A cool blue-tinted near-black; the deepest surface. The brass and the type carry the warmth, the ground stays cool.
- **Panel Slate** (`oklch(0.22 0.014 250)`): cards, panels, the primary raised surface.
- **Raised Slate** (`oklch(0.26 0.015 250)`): nested panels, input wells, hover rows.
- **Steel Line** (`oklch(0.34 0.012 250)`): 1px hairline borders and dividers — never a colored stripe.
- **Filament** (`oklch(0.95 0.006 250)`): primary text and headings — a cool near-white (high contrast on Console Slate, comfortably AAA).
- **Filament Soft** (`oklch(0.82 0.008 250)`): secondary prose that must still clear AAA.
- **Filament Dim** (`oklch(0.68 0.010 250)`): labels and metadata; body copy uses Filament, not this.

### Status (security / operational signal only)
Each state is a **tonal pair**: a lifted signal tone (icon/text) over a deep same-hue surface ground — the dark-ground inversion of Obsign's pale-ground badges. Hues are chosen to sit clear of the brass accent.
- **Verified Green** — `oklch(0.74 0.13 150)` on surface `oklch(0.28 0.06 150)`: a device/request authorized; live and good.
- **Caution Amber** — `oklch(0.72 0.15 50)` on surface `oklch(0.28 0.07 50)`: attention needed. Pushed orange (hue 50) to stay clear of the brass accent (hue 80).
- **Alarm Red** — `oklch(0.65 0.18 25)` on surface `oklch(0.28 0.09 25)`; solid fill **Alarm Solid** (`oklch(0.58 0.21 25)`) with light text for a destructive confirm.
- **Calm Slate** — `oklch(0.70 0.10 240)` on surface `oklch(0.28 0.05 240)`: neutral information.

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

<!-- SEED: no components exist yet (the Tauri app is a later implementation phase). The intended canonical vocabulary is sketched below; real tokens, states, and the design.json sidecar land on the scan-mode re-run. -->

Intended primitives, in this register's character:
- **Buttons** — precise, tight radius (≈6px, tighter than stock-iOS); **Primary** is a Sealing-Wax Gold fill with deep-slate text (the One-Lamp action); **Secondary/Ghost** is Panel Slate with a Steel Line border; **Destructive** is Alarm Solid, reserved for the irreversible revoke/confirm. Full state set required (default/hover/focus-visible/active/disabled/loading).
- **Code Output** *(signature component)* — a claim code or `did:key` rendered as copyable terminal-style output in mono on Raised Slate, with a leading prompt glyph and a copy affordance; never truncated, wraps `break-all`. This is the demo-lifesaver surface.
- **Device Row** — a dense, aligned list row (`ls -l` legibility): label, mono device-ID, last-seen, and a status chip; full-size tap targets despite density.
- **Status Chip** — the tonal-pair badge; color + glyph (`● active` / `⊘ revoked` / `! error`) + label, never color alone.
- **Inputs** — Raised Slate well, Steel Line border, gold focus ring; mono for fields that take a code or URL.
- **Focus-visible** — a 2px gold ring with offset on every interactive element; never removed (visible focus is a security feature here).

## 6. Do's and Don'ts

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
