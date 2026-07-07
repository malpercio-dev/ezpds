---
name: Obsign
description: A serious security instrument for holding and defending your self-sovereign identity.
# Colors are OKLCH-canonical (impeccable's OKLCH-throughout doctrine). Stitch's linter
# prefers hex and will warn; OKLCH is the source of truth here. Do not redefine these as hex elsewhere.
# Values below are the LIGHT appearance (canonical). The dark-appearance counterparts live as
# light-dark() pairs in apps/identity-wallet/src/lib/styles/tokens.css and are specified in §2.
colors:
  # — Brand: The Seal —
  primary: "oklch(0.46 0.105 62)"        # Sealing-Wax Gold — primary actions, brand mark, the seal
  primary-deep: "oklch(0.38 0.090 60)"   # pressed/active gold
  accent: "oklch(0.34 0.10 330)"         # Aubergine — links, "advanced/cryptographic detail" affordances
  accent-deep: "oklch(0.28 0.09 330)"    # pressed/active aubergine
  seal-pale: "oklch(0.92 0.055 80)"      # pale gold ground for "verified / sealed" marks (takes ink text)
  on-color: "oklch(0.99 0.005 80)"       # near-white text on saturated fills (gold / aubergine / solid red)
  # — Neutral: Archival paper & ink —
  bg: "oklch(1 0 0)"                     # pure white — the gold + aubergine carry the brand, not the surface
  surface: "oklch(0.975 0.004 75)"       # sealed parchment — cards, panels
  surface-sunk: "oklch(0.955 0.005 75)"  # inset / nested panels
  ink: "oklch(0.23 0.012 60)"            # archival ink — body text (≈13:1 on bg, AAA)
  muted: "oklch(0.42 0.012 60)"          # faded ink — secondary labels (≈5.6:1; AAA body uses ink)
  line: "oklch(0.90 0.004 75)"           # hairline — 1px borders & dividers (never a colored stripe)
  # — Status signal (deep text/icon tones; always paired with icon + label, never color alone) —
  safe: "oklch(0.40 0.10 150)"           # Verified green
  warning: "oklch(0.42 0.10 60)"         # Caution amber (deep enough to never be confused with brand gold)
  critical: "oklch(0.44 0.16 25)"        # Alarm red
  expired: "oklch(0.42 0.02 25)"         # Closed/inert — deliberately ASHEN, distinct from critical
  info: "oklch(0.42 0.07 250)"           # Calm slate
  critical-solid: "oklch(0.52 0.20 25)"  # solid alarm fill for the override CTA (takes on-color text)
  # — Status surface (pale grounds for tonal badges; pair each with its deep signal tone above) —
  safe-surface: "oklch(0.95 0.045 150)"
  warning-surface: "oklch(0.95 0.055 75)"
  critical-surface: "oklch(0.95 0.045 25)"
  expired-surface: "oklch(0.95 0.004 25)" # near-neutral — reads "closed", not "alarm"
  info-surface: "oklch(0.95 0.030 250)"
typography:
  display:
    fontFamily: "Libre Caslon Display, Georgia, serif"
    fontSize: "1.75rem"
    fontWeight: 400
    lineHeight: 1.15
    letterSpacing: "normal"
  headline:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "-0.005em"
  title:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "normal"
  body:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.55
    letterSpacing: "normal"
  label:
    fontFamily: "Public Sans, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "0.01em"
  data:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "4px"
  md: "8px"
  lg: "12px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  2xl: "48px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-color}"
    rounded: "{rounded.md}"
    padding: "12px 20px"
    typography: "{typography.label}"
  button-primary-hover:
    backgroundColor: "{colors.primary-deep}"
    textColor: "{colors.on-color}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "12px 20px"
    typography: "{typography.label}"
  button-destructive:
    backgroundColor: "{colors.critical-solid}"
    textColor: "{colors.on-color}"
    rounded: "{rounded.md}"
    padding: "12px 20px"
    typography: "{typography.label}"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "20px"
  input:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "12px 14px"
  status-badge-critical:
    backgroundColor: "{colors.critical-surface}"
    textColor: "{colors.critical}"
    rounded: "{rounded.sm}"
    padding: "4px 10px"
    typography: "{typography.label}"
---

# Design System: Obsign

## 1. Overview

**Creative North Star: "The Sealed Credential"**

This is the wax seal, the embossed foil on a passport, the notary's stamp — authenticity made visible, and held by the person it belongs to. The wallet guards the keys to someone's entire decentralized identity, so it must *feel* as rigorous as the cryptography beneath it: a serious security instrument, not an app with a lock icon. Gravitas here comes from precision and restraint — exact alignment, deliberate type, a monospace that tells the literal truth of a key — never from chrome, darkness, or decoration. It lives in the humane, light tradition of **Proton** and **1Password**: trustworthy without being cold, principled without being grim. The user should sit down and think *"this is solid; I understand what it's doing; my identity is genuinely safe here."*

Gold is the load-bearing idea, and it is gold-as-**authenticity**, never gold-as-money. Sealing-wax gold and aubergine on archival white evoke an official credential — a stamped, sovereign document — and pointedly reject the shiny, metallic, neon register of crypto. The surface stays pure white so the brand lives in the seal and the type, not in a tinted "warm" wash. The system is calm at rest and unmistakable under alarm: when an attacker touches the identity, a 72-hour clock starts, and every pixel on that path exists to make the stakes and the single right action impossible to misread.

This system explicitly rejects: **crypto/web3 hype** (neon, coins, gradients-to-the-moon), the **enterprise dashboard** (dense admin panels, SaaS-cream, chart-soup), anything **playful or gamified** (mascots, confetti, reward badges, rainbow avatars), **generic stock-iOS** (system blue, SF-only, 12px pills with no identity), and **Ledger-style dark-technical heaviness** (dark-by-default, asset-vault gloom).

**Key Characteristics:**
- Sealing-wax gold + aubergine on pure white — authenticity, not currency.
- A serious instrument: precision over polish, restraint over decoration.
- Light and humane (Proton / 1Password lane) as the canonical appearance; follows the system into a warm "archive at night" dark appearance (§2) — humane dark, never dark-and-heavy, never dark-by-default.
- Monospace tells the literal truth; progressive disclosure hides it until asked.
- Status is *never* color alone — it is color + icon + label + position.
- WCAG 2.2 AAA is the target, because a high-assurance tool owes a high-assurance interface.

## 2. Colors: The Sealed-Credential Palette

A two-brand-color system — sealing-wax gold and aubergine — on pure-white archival paper, with a disciplined status ramp reserved entirely for security state.

### Primary
- **Sealing-Wax Gold** (`oklch(0.46 0.105 62)`): the seal. Primary actions, the brand mark, the "verified/sealed" moment. Deliberately deep and dry — a brass-and-wax gold that holds near-white text (~5.5:1), not a bright leaf-gold that would read decorative or crypto. Pressed state **Deep Wax** (`oklch(0.38 0.090 60)`).
- **Pale Seal** (`oklch(0.92 0.055 80)`): the pale gold ground for small "sealed / verified" marks where dark ink text sits on top. The only place gold goes light.

### Secondary
- **Aubergine** (`oklch(0.34 0.10 330)`): the second brand voice and the color of *depth on demand*. Links, and the affordances that reveal cryptographic machinery (the "advanced / details" disclosures — DIDs, rotation keys, audit logs). A quiet nod to Proton's purple without copying it. Pressed state (`oklch(0.28 0.09 330)`).

### Neutral
- **Archival Ink** (`oklch(0.23 0.012 60)`): body text and headings. ~13:1 on white — comfortably AAA. Carries a barely-there warmth toward the brand hue so it never reads as cold pure-black.
- **Faded Ink** (`oklch(0.42 0.012 60)`): secondary labels and metadata (~5.6:1). Real body copy uses Archival Ink, not this, to hold the 7:1 AAA line.
- **Pure White** (`oklch(1 0 0)`): the page. No hidden warmth — the brand carries warmth, the surface does not.
- **Sealed Parchment** (`oklch(0.975 0.004 75)`) / **Sunk Parchment** (`oklch(0.955 0.005 75)`): cards, panels, and inset regions — the second neutral layer, a hair warm.
- **Hairline** (`oklch(0.90 0.004 75)`): 1px borders and dividers. Depth is a hairline and a tonal step, never a drop shadow at rest.

### Status (security signal only)
Each state is a **tonal pair**: a pale surface ground plus a deep same-hue ink/icon tone. This is what makes the badges AAA-legible *and* lets them coexist with a gold brand without confusion.
- **Verified Green** — ink `oklch(0.40 0.10 150)` on `oklch(0.95 0.045 150)`: a key the device authorized; the identity is safe.
- **Caution Amber** — ink `oklch(0.42 0.10 60)` on `oklch(0.95 0.055 75)`: attention needed; deep enough to never be mistaken for the brand gold.
- **Alarm Red** — ink `oklch(0.44 0.16 25)` on `oklch(0.95 0.045 25)`; solid fill **Alarm Solid** (`oklch(0.52 0.20 25)`) with near-white text for the override CTA: an unauthorized change, clock running.
- **Closed/Expired** — ink `oklch(0.42 0.02 25)` on `oklch(0.95 0.004 25)`: deliberately **ashen and desaturated** so an elapsed recovery window reads as *closed and inert*, not *act now*. It must not look like Alarm Red.
- **Calm Slate** — ink `oklch(0.42 0.07 250)` on `oklch(0.95 0.030 250)`: neutral information.

### Named Rules
**The Seal-vs-Signal Rule.** Gold is *identity*; the green/amber/red/slate ramp is *status*. Status colors always carry an icon and a text label and appear only in status contexts. Gold never masquerades as a status, and a status color never carries the brand.

**The Authenticity-Not-Currency Rule.** Gold is always matte, dry, editorial — a wax seal. Never metallic gradients, never coin shapes, never glint. The moment gold looks like money, it has become a crypto anti-reference.

**The Pure-Surface Rule.** In the light appearance the page is pure white (`oklch(1 0 0)`). Warmth comes from the seal and the type. Tinting the background "to feel warm" is forbidden — it's the AI-cream cliché and it muddies AAA contrast.

### Dark appearance (system-follow)

The app follows the iOS system appearance — `color-scheme: light dark`, with every color token a `light-dark()` pair in `apps/identity-wallet/src/lib/styles/tokens.css`. Dark exists for the *user*, not the brand: the alarm path — a person woken at 2 a.m. by a PLC alert, phone set to dark — must not open with a pure-white flash. The dark appearance is **the archive at night**, the same room with the lights low, not a different product:

- **The Same-Seal Rule.** The wax seal is a physical object; it keeps its color at night. `primary`, `primary-deep`, `critical-solid`, `on-color`, the DID-avatar fill, and the emboss material effects are appearance-invariant.
- **The Warm-Ground Rule.** The dark ground is the ink itself — near-black at the brand's warm hue (`oklch(0.18 0.012 60)`), never a cold blue-black. Cold-dark *is* the Ledger anti-reference; warm-dark is ours.
- **The Inverted-Elevation Rule.** In light, raised surfaces step *darker* than the white page (parchment); in dark they step *lighter* (page `0.18` → card `0.23`, inset `0.205` between). Depth is still tonal layers + hairlines, never a shadow at rest.
- **Status pairs invert; meaning survives.** Each tonal pair flips to a light same-hue ink on a dim same-hue ground (e.g. Alarm Red becomes `oklch(0.82 0.095 25)` on `oklch(0.26 0.055 25)`). Critical stays alarm, Expired stays ashen, and the two remain visually distinct in both appearances.
- **Aubergine lifts to lavender-aubergine** (`oklch(0.76 0.07 330)`) so links and the 2px focus ring hold AAA on the dark ground; gold-as-text roles (`gold-ink`, `gold-soft`, `seal-glyph`) lift the same way while gold-as-fill stays put.
- **AAA holds in both appearances.** Every text pairing is verified ≥7:1 (body and status text), ≥4.5:1 (labels), ≥3:1 (large glyphs and non-text) in dark exactly as in light. Never eyeball a dark value — verify it.

Read the anti-reference precisely: "Ledger-style dark-technical heaviness" means dark **as brand register** — dark-by-default asset-vault gloom. Honoring the user's system setting with a humane warm dark is not that; shipping dark as the default would be.

## 3. Typography

**Display Font — the signet:** Libre Caslon Display, serif (with `Georgia` fallback)
**UI / Body Font:** Public Sans (with `system-ui` fallback)
**Data / Mono Font:** JetBrains Mono (with `ui-monospace` fallback)

**Character:** A three-font system that stages the metaphor. **Public Sans** — the typeface of the U.S. government design system, the sober workhorse of official identity documents — carries every working surface: headings, body, buttons, labels. It reads sovereign and trustworthy, with neither brand-y warmth nor enterprise chill. Above it, **Libre Caslon Display** is the *signet*: an engraved old-style serif (Caslon set the Declaration of Independence) reserved for the single ceremonial display moment on a screen — the wordmark, a hero line, an identity's monogram. Its rarity is what makes it read as a stamped seal rather than decoration. **JetBrains Mono** carries the literal truth — DIDs, keys, CIDs — with a tall x-height and unmistakable character shapes built for reading code under pressure. The scale is a **fixed rem** modular scale (~1.2 ratio), never fluid `clamp()`: users view at a consistent DPI, and a heading that shrinks in a panel looks worse, not better.

### Hierarchy
- **Display** (Libre Caslon Display, 400, 1.75rem, 1.15): the one signet moment per screen — the wordmark, a hero line, a document title. Serif. Mobile-restrained; no shouting hero scales.
- **Headline** (Public Sans, 600, 1.375rem, 1.2): section and screen headings — the working voice.
- **Title** (Public Sans, 600, 1.125rem, 1.3): card titles, group headers, the handle on an identity.
- **Body** (Public Sans, 400, 1rem, 1.55): prose and explanations. Cap measure at 65–75ch. Uses Archival Ink for the AAA 7:1 line.
- **Label** (Public Sans, 500, 0.8125rem, +0.01em): buttons, field labels, metadata. Sentence case by default.
- **Data** (JetBrains Mono, 0.875rem, 1.5): DIDs, public keys, CIDs, audit-log values — anything literal and verifiable. Always wraps with `break-all`; never truncates a key silently.

### Named Rules
**The Signet Rule.** Libre Caslon Display appears at most once per screen, for the single ceremonial display moment. Everything that works — headings, labels, buttons, data — is Public Sans or JetBrains Mono. The serif is a seal, and a seal you stamp twice is a smudge.

**The Literal-Truth Rule.** Every cryptographic value — DID, rotation key, CID, signature — is set in JetBrains Mono. Monospace signals "this is exact, verify it character by character." Proportional type is for prose, never for keys.

**The No-Eyebrow Rule.** No tiny uppercase tracked kicker above every section. One screen, one clear headline. Labels are sentence case; ALL-CAPS is reserved for nothing decorative.

## 4. Elevation

Flat by default. Depth is built from **tonal layers** (white page → parchment surface → sunk parchment) and **hairline borders**, not from drop shadows. A resting card is a parchment rectangle with a 1px hairline — no shadow. This is what keeps the system from sliding into either the 2014-app look or the enterprise card-soup look, and it reads as precise and instrument-grade.

Shadows appear only when an element genuinely floats above the page and the user must understand it as *temporary and modal*: the recovery-override confirmation sheet, and toasts. Two tokens, both soft and neutral — never colored, never decorative.

### Shadow Vocabulary
- **Sheet** (`box-shadow: 0 -8px 32px oklch(0.23 0.012 60 / 0.14)`): the override/confirmation sheet rising from the bottom.
- **Toast** (`box-shadow: 0 4px 20px oklch(0.23 0.012 60 / 0.16)`): transient status notifications.

In the dark appearance both tokens deepen to true black at higher opacity (`oklch(0 0 0 / 0.55)` / `oklch(0 0 0 / 0.6)`) — an ink-tinted shadow vanishes against the night ground, and a floating surface must still read as floating.

### Named Rules
**The Flat-At-Rest Rule.** Surfaces are flat with a hairline at rest. A shadow is a response to *floating* (modal, toast) — a state, not a decoration. If a card has a shadow just sitting there, the shadow is wrong.

## 5. Components

Every interactive component ships its full state set — default, hover, focus-visible, active, disabled, loading, error — and the vocabulary is identical across every screen. A button that means "primary" looks the same in onboarding and on the alert screen.

### Buttons
- **Shape:** precise, not pill — 8px radius (`{rounded.md}`). Pointedly tighter than the stock-iOS 12px so it reads considered, not default.
- **Primary:** Sealing-Wax Gold fill, near-white label, 12px/20px padding. The seal. Hover → Deep Wax; active → Deep Wax + 1px inset; disabled → 40% toward parchment with Faded Ink label.
- **Secondary / Ghost:** Parchment fill, Archival Ink label, 1px hairline border. The quiet default for non-committing actions.
- **Destructive (Override):** Alarm-Solid fill, near-white label — used *only* for the irreversible recovery-override action, and only when the user has reviewed the operation. Gravity by scarcity.
- **Focus-visible:** a 2px Aubergine ring with a 2px offset on every interactive element — never removed. Visible keyboard focus is a security feature here, not a nicety.

### Cards / Containers
- **Corner Style:** 12px (`{rounded.lg}`).
- **Background:** Sealed Parchment on the white page.
- **Shadow Strategy:** none at rest (see Elevation).
- **Border:** 1px Hairline.
- **Internal Padding:** 20px (`lg`/`md`). Generous — depth comes from breathing room, not density. (Density is the enterprise anti-reference.)

### Inputs / Fields
- **Style:** white field, 1px Hairline, 8px radius, Archival Ink text.
- **Focus:** border shifts to Aubergine + the 2px focus ring. No glow.
- **Error:** Alarm-Red 1px border + a mono-or-sans error message in Alarm-Red ink, with an icon. Never color alone.
- **Mono fields:** inputs that accept a DID or handle use JetBrains Mono.

### Status / Urgency Badge — *the signature component*
The crown jewel and the highest-stakes UI in the app. A badge that says how safe an identity is and, under attack, how long until the recovery window closes. **It is never color alone.** Each state is the union of four signals:

| State | Color (tonal pair) | Icon | Label | Position/behavior |
|-------|--------------------|------|-------|-------------------|
| Safe | Verified Green | ✓ shield | "Secure" | calm, static |
| Warning | Caution Amber | △ triangle | "Action needed" | — |
| Critical | Alarm Red | ◆ alert | live `"Xh Ym remaining"` | counts down every 60s |
| Expired | Ashen/Closed | ⊘ lock | "Recovery window closed" | inert, override disabled |

The countdown is announced to VoiceOver as text, not implied by a colored dot. Critical and Expired must be visually distinct — alarm vs. closed — so a colorblind user under attack can never confuse "act now" with "too late."

### DID Avatar
A deterministic identity mark — a hue derived by hash from the DID, so the same identity always renders the same color. Reconcile it with the system: constrain the derived color to the brand's chroma and a fixed lightness (e.g. `oklch(0.55 0.09 <hash-hue>)`), so a wall of identities reads as a coherent, muted set of seals — not rainbow confetti (which would be the playful anti-reference). The monogram initial is set in Libre Caslon Display — an engraved letter, the seal made personal.

### Navigation
The app is a calm state-machine flow, not a chrome-heavy shell. A single back affordance (Aubergine, sentence-case "Back"), a clear screen title, and nothing competing with it. No tab bars of decorative icons, no persistent dense nav.

## 6. Brand Mark & App Icon

**The mark is the sealed credential made literal:** the app's own `SealEmblem` brand
moment — a sealing-wax-gold seal holding the shield-check, the emblem every ceremonial
screen already opens with — promoted to the home screen. The seal sits on the archival
white-to-parchment page, pressed with the embossed pale ring and the near-white
shield-check. Its edge is a *gentle, deterministic undulation*, not a perfect circle
and not a splat: a circle would read as a coin (the Authenticity-Not-Currency rule);
a wild blob would break the precision-and-restraint register.

- **Files:** [`apps/identity-wallet/app-icon.svg`](apps/identity-wallet/app-icon.svg)
  (vector source of truth, geometry and colors documented inline) →
  `apps/identity-wallet/app-icon.png` (the 1024×1024 render `cargo tauri icon`
  consumes). `just ios-postinit` (Patch G) regenerates the iOS asset catalog from it
  after every `cargo tauri ios init`; `just ios-check` verifies via a sha256 marker.
- **iOS 26 fit:** drawn full-bleed on the square with no baked-in corner radius or
  gloss — the system applies the squircle mask and Liquid Glass material. The SVG's
  `layer-background` / `layer-glyph` groups are Icon Composer seams if the mark is
  ever rebuilt as a layered `.icon` file. Wax gradients are shallow and matte, never
  metallic glint.
- **Sibling relationship:** the deliberate inverse of the Custos Companion icon
  (`apps/admin-companion/app-icon.svg`, its DESIGN.md §6) — same gold family, light
  archival ground vs. cool console slate, the seal vs. the operator's prompt. The two
  read as one house on a home screen without being a reskin of each other.

## 7. Do's and Don'ts

### Do:
- **Do** treat gold as a wax seal — matte, dry, editorial (`oklch(0.46 0.105 62)`). Authenticity, sovereignty, an official stamp.
- **Do** keep the page pure white (`oklch(1 0 0)`) in the light appearance and let the seal and type carry the brand; in dark, the ground is the warm near-black of §2's Dark appearance.
- **Do** hold WCAG 2.2 AAA in **both appearances** — Archival Ink body on white is ~13:1, night ink on the dark ground ~16:1; verify every text-on-color pairing, light and dark.
- **Do** signal status with color **and** an icon **and** a text label **and** position — always all four.
- **Do** keep Critical and Expired visually distinct: alarm-red that acts vs. ashen-slate that's closed.
- **Do** set every DID, key, CID, and signature in JetBrains Mono — the literal truth, verifiable character by character.
- **Do** lead with plain human stakes ("someone is trying to take your identity") and tuck the cryptographic machinery one Aubergine tap behind a "details/advanced" disclosure.
- **Do** keep a visible 2px Aubergine focus ring on every interactive element.
- **Do** stay flat at rest; reserve the two soft shadows for floating sheets and toasts.

### Don't:
- **Don't** let gold look like money — no metallic gradients, coin shapes, glint, or "to the moon." The instant it reads as currency it has become the **crypto/web3** anti-reference.
- **Don't** build the **enterprise dashboard**: no dense admin panels, SaaS-cream backgrounds, or chart-soup. Reach depth by progressive disclosure, never by dumping density on screen one.
- **Don't** go **playful / gamified**: no mascots, confetti, reward badges, streaks, or rainbow avatars. Losing an identity to an attacker is too real to gamify.
- **Don't** ship **generic stock-iOS**: not system blue `#007aff`, not SF-only, not 12px pills on everything with no identity of its own.
- **Don't** go **Ledger-dark**: dark-technical, asset-vault heaviness is the wrong register. This is light and humane — the dark appearance is §2's warm archive-at-night, system-follow only, never dark-by-default and never cold blue-black.
- **Don't** signal urgency by color alone — a colorblind user under attack must never have to guess.
- **Don't** tint the background "to feel warm" — that's the AI-cream cliché and it erodes contrast.
- **Don't** use a `border-left`/`border-right` colored stripe on cards or alerts; use a full 1px hairline, a tonal ground, or a leading icon.
- **Don't** use gradient-clipped text, decorative glassmorphism, or a big-number hero-metric template.
- **Don't** put a tiny uppercase tracked eyebrow above every section.
