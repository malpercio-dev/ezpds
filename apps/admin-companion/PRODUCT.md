# Product

> Scope: this file describes the **admin-companion** mobile app (`apps/admin-companion/`),
> the operator-facing iOS admin tool for an ezpds relay. It is the design source-of-truth that
> every `/impeccable` command targeting this app reads. It is a **separate product** from the
> identity-wallet (Obsign, `apps/identity-wallet/PRODUCT.md`) and deliberately speaks a different
> design language, because its audience and its job are different.
>
> See the design plan: `docs/archive/design-plans/2026-06-26-admin-companion-app.md`.

## Register

product

## Users

The **operator** who self-hosts an ezpds relay — and, today, administers it from a terminal with `curl`, the Bruno collection, or an SSH session into the box. They are technical: they know what a bearer token, an HTTP status code, a `did:key`, and a P-256 signature are, and they would rather read exact output than be walked through a friendly flow. This is the person who set the relay up; they are not anxious about it, they are *in command* of it.

They reach for this app in two modes, both confident and time-conscious:
1. **On-the-go admin (frequent, fast, low-drama).** Mint and hand someone an account claim code during a demo or a hallway conversation; check who's paired; glance at relay state — the things they'd normally SSH in for, done from a pocket in seconds.
2. **Loss response (rare, deliberate, not panicked).** A phone is lost or retired. The operator revokes that device from another paired device or the laptop, and confirms it can no longer act. Composed cleanup, not an alarm.

**Job to be done:** *"Let me run my relay from my pocket — do the admin action I'd normally open a terminal for, fast and unambiguously — and trust that this device can never become a liability if I lose it."*

This audience is the deliberate inverse of Obsign's. Obsign serves a possibly-non-technical person in a high-adrenaline attack; this serves a technical person in calm command. The wallet hides the machinery behind plain human stakes; this app **shows** the machinery, because the machinery is the operator's native language.

## Product Purpose

A mobile (iOS) **operator console** for an ezpds relay. It lets the person hosting the relay:
- **Generate and share account claim codes** on demand — the demo-lifesaver that motivated the app.
- **Enroll this device** as an authorized admin via QR pairing bootstrapped by the relay's master admin token.
- **Manage paired admin devices** — list them with their status, and revoke any one (the lost-phone case) without needing the phone itself.

Authentication is per-device and key-based: each phone holds a P-256 key in the Secure Enclave and **signs every request**, so there is no replayable admin secret sitting on the device. The relay's existing static master token stays as the root of trust and break-glass path.

It exists because relay administration today requires a laptop and a terminal — fine at a desk, useless in the moment you're standing in front of someone who needs a claim code. This app puts the narrow, high-value slice of operator actions where the operator actually is.

**Success looks like:** an operator pulls out their phone mid-conversation, mints a claim code, and shares it before the other person has finished asking — and never once worries that the phone in their pocket is a way into their relay. Failure is an admin tool so fiddly the operator goes back to SSH, or one whose security model makes a lost phone a breach.

## Brand Personality

A **precision operator instrument** in the lineage of a well-made developer tool — the refined-terminal lane of **Warp**, **Charm/Bubbletea**, and the dense-but-legible operator surfaces of **Linear** and **Railway**. It is the technical sibling of Obsign: same security DNA, opposite manner.

- **Three words:** Operator. Exact. Fast.
- **Voice & tone:** terse and technical. It speaks the operator's language — status codes, glyphs, monospace truth — and trusts them to read it. No onboarding warmth, no reassurance copy, no hand-holding. Confident and direct, never sloppy. Where Obsign explains, this *reports*.
- **Emotional goal:** command and speed. The operator should feel *"this is mine, it does exactly what I'd do from the terminal, and it does it faster."*
- **Where the gravitas comes from:** precision and information density done right — aligned columns, monospace where data is literal, a calm dark surface, exact spacing — **not** from chrome and **not** from hacker theatrics. The product should feel as rigorous as the keys it signs with.
- **Relationship to Obsign:** shares the OKLCH token *architecture* and the security-instrument seriousness, but forks the register — dark-first, monospace-forward, operator-terse. It is not a reskin of the wallet and must not read as one.

## Anti-references

What this must **not** look like:

- **Hacker cosplay / terminal kitsch.** No CRT scanlines, no phosphor-glow bloom, no Matrix rain, no `h4ck3r` ransom-note green-on-black, no fake boot logs as decoration. "Terminal-native" means a *refined* command surface, not a costume. The instant it looks like a movie hacker's screen, it has failed.
- **Consumer-app friendliness (Obsign's lane).** No humane onboarding carousels, no soft playful cards, no mascots, no emoji-led empty states, no reassurance copy. This audience finds that condescending.
- **Crypto / web3 hype.** Same live trap as the wallet, given the keys/DID/signature vocabulary — no neon gradients, coin iconography, or speculative-finance energy. This is infrastructure, not a token.
- **Enterprise dashboard / chart-soup.** Density is welcome, but as legible operator *output* — aligned, scannable, monospace — never as SaaS analytics widgets, gauge clusters, or KPI hero cards.
- **The low-contrast dark-theme cliché.** Dark-first is not permission for gray-on-darker-gray mush. Muddy, sub-AAA dark palettes are the most common failure of this register and are forbidden here.

## Design Principles

1. **Speak the operator's language.** Lead with the literal — status codes, glyphs, `did:key` values, exact timestamps — reported the way a terminal would, not translated into soft consumer phrasing. This audience reads output; show it the exact truth. Where Obsign hides the cryptographic machinery one tap away, this app leads with it.
2. **Density with legibility.** Operators want information per screen, not one big number. Deliver it as aligned, scannable rows — the legibility of a good `ls -l`, never chart-soup and never mush. Depth comes from precise alignment, not decoration.
3. **Speed is the feature.** The core loop — mint a claim code, share it — must complete in seconds: open, authenticate with biometrics, done. Every tap that isn't the action is friction to be removed. The win condition is "faster than opening a terminal."
4. **Practice the assurance you preach.** *(Carried verbatim from Obsign — it is the same security DNA.)* This app can mint credentials and revoke admin access. A tool that holds that power but is sloppy in its interface contradicts itself. Per-device keys, biometric-gated signing, honest revocation states, and a rigorous accessibility bar *are* the brand.
5. **Refined, not costume.** Terminal-native is an aesthetic of restraint and precision — a calm dark ground, exact monospace, disciplined color — not hacker theatrics. When in doubt, choose the version a senior infrastructure engineer would respect, not the one that looks "cyber."
6. **Honest states under loss.** The lost-phone path (a revoked device) must read unmistakably and route forward to re-pairing, never dead-end in a cryptic error. Calm competence under loss, not alarm — the operator is cleaning up, not under attack.

## Accessibility & Inclusion

- **Target WCAG 2.2 AAA, even dark-first.** 7:1 for normal text, 4.5:1 for large — held against a dark ground, where it is hardest. Dark operator palettes fail contrast constantly; this one must not. Treat AA as the floor. *(The one Obsign principle carried with zero compromise.)*
- **Status is never color alone.** Device and request state (`active` / `revoked` / `pending` / `error`) always pairs color with an explicit **glyph, text label, and position** — e.g. `● active`, `⊘ revoked`, `! error` — so a colorblind operator can never misread which device is live. A correctness requirement, not a nicety.
- **Monospace legibility under Dynamic Type.** Claim codes, `did:key`s, and device IDs scale with the system setting, stay legible at large sizes, and **never truncate silently** — they wrap (`break-all`), mirroring Obsign's Literal-Truth rule. A half-shown code is a support ticket.
- **Reduced motion honored.** Any transition has a `prefers-reduced-motion` alternative. Motion conveys state only — never decoration, and never a fake-terminal typing animation.
- **44×44pt minimum touch targets** (iOS HIG) — density is of *information*, not of tap targets. The revoke and generate actions especially get full-size, unambiguous hit areas.
- **VoiceOver.** Status, claim codes, and device IDs are announced as meaningful text, never implied by a colored dot. A code the operator is about to read aloud must be perceivable to a screen reader.
