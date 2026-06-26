# Product

> Scope: this file describes the **identity-wallet** mobile app (`apps/identity-wallet/`),
> the only frontend surface in the ezpds repo. It is the design source-of-truth that every
> `/impeccable` command reads. The rest of the repo is the Rust backend (pds, crypto, repo-engine).

## Register

product

## Users

People who want to **own their digital identity outright** rather than renting it from a platform. On the AT Protocol (the network behind Bluesky), an identity is a `did:plc`, and whoever holds its rotation keys controls it. This wallet puts those keys in the user's own pocket.

The audience spans a spectrum, served by progressive disclosure:
- **Sovereignty-minded / crypto-literate** users who understand DIDs, rotation keys, and audit logs, and want to verify everything themselves.
- **Mainstream** users who don't know what a DID is but understand "this is my account and nobody should be able to steal it."

They use the app in two very different emotional modes:
1. **Calm setup (one-time, unhurried, high-stakes).** Create or import an identity, custody a device key in the Secure Enclave, stash a Shamir recovery share. Deliberate, careful, not urgent.
2. **Alarm response (rare, stressful, time-boxed).** A background monitor detects an *unauthorized* change to their identity on the public PLC directory and fires an alert. The user may be under active attack, on mobile, adrenaline up — and racing a hard **72-hour** recovery window to override the malicious operation before it becomes permanent.

**Job to be done:** *"Let me hold and defend my own identity — set it up once with confidence, and if someone tries to hijack it, tell me clearly and help me take it back before the clock runs out."*

## Product Purpose

A mobile (iOS) **wallet for self-sovereign decentralized identity** on the AT Protocol. It lets a person:
- **Create or import** a `did:plc` identity.
- **Custody the controlling keys on-device** (Secure Enclave on real hardware; software P-256 in simulator).
- **Back them up resiliently** via a Shamir secret split.
- **Continuously monitor** the public PLC directory for unauthorized changes, and — when one is detected — alert the user and walk them through a **time-boxed recovery override** to reclaim the identity.

It exists because on AT Proto, *identity control is key control* — and today that control is effectively delegated to hosting providers. This wallet returns it to the individual.

**Success looks like:** a user trusts this app with the keys to their entire online identity; sets it up without confusion; and, in the rare and frightening moment of an attack, understands exactly what is happening and successfully reclaims their identity inside the recovery window. Failure is a user who misreads an alert, hesitates, or doesn't understand the stakes — and loses their identity.

## Brand Personality

A **serious security instrument** in the *humane* tradition of **Proton** and **1Password** — deliberately not the dark, asset-heavy gravitas of a hardware-wallet companion app.

- **Three words:** Sovereign. Precise. Trustworthy.
- **Voice & tone:** plain-spoken, exact, and calm under pressure. Honest about stakes without ever inducing panic or selling fear. No hype, no jargon dumped on the user, no false reassurance.
- **Emotional goal:** confidence and control. The user should feel *"This is solid. I understand what it's doing. My identity is genuinely safe here."*
- **Where the gravitas comes from:** precision and restraint — exact alignment, deliberate typography, monospace where data is literal, a high-assurance accessibility bar — **not** from added chrome, darkness, or weight. The product should feel as rigorous as the cryptography beneath it.

## Anti-references

What this must **not** look like:

- **Crypto / web3 hype.** No neon gradients, coin iconography, speculative-finance energy, "to the moon." This is identity sovereignty, not a token. (A live trap, given the wallet/keys/DID vocabulary.)
- **Enterprise dashboard.** No dense corporate admin panels, SaaS-cream backgrounds, or chart-soup. Depth is reached by progressive disclosure, never by dumping density onto the first screen.
- **Playful / gamified.** No mascots, confetti, achievement badges, streaks, or game mechanics. Losing your identity to an attacker is too real to gamify.
- **Generic stock-iOS.** The current screens are essentially default iOS (system blue, system font, no identity). Don't stay generic — develop a real, ownable visual voice.
- **Ledger-style dark-technical heaviness.** The chosen touchstones (Proton, 1Password) are deliberately the lighter, more humane end of "serious." Avoid drifting toward device-forward, dark, asset-guarding aesthetics.

## Design Principles

1. **Clarity is the security feature.** A user who misunderstands a screen can lose their identity. Every view must make the true state and the single right next action unmistakable. Trust is earned through legibility, not reassurance theater.
2. **Calm under alarm.** The app's hardest moment is a live attack on a 72-hour clock. Design the alarm path for a stressed human: unambiguous stakes, one clear action, no panic-inducing noise. Gravitas, not adrenaline.
3. **Progressive disclosure of the machinery.** Lead with plain human stakes ("someone is trying to take your identity"); keep the cryptographic truth (DIDs, rotation keys, audit logs, signatures) one deliberate tap away for those who want to verify. Never hide it; never force it.
4. **Practice the assurance you preach.** This holds the keys to a person's entire online identity. A high-assurance tool that is sloppy in its UI contradicts itself — precision, restraint, and a rigorous accessibility bar *are* the brand.
5. **Honest, never hype.** State stakes truthfully without selling fear or fortune. No web3 theatrics, no dark-pattern urgency, no gamified dopamine. Confidence comes from substance.

## Accessibility & Inclusion

- **Target WCAG 2.2 AAA (high-assurance).** 7:1 contrast for normal text, 4.5:1 for large text; treat AA as the floor and reach AAA wherever feasible. A security-critical tool holds itself to a security-critical accessibility bar.
- **Status is never color alone.** The urgency system (`safe` / `warning` / `critical` / `expired`) must always pair color with explicit **text, icon/shape, and position**, so colorblind users (deuteranopia/protanopia especially, given the green/amber/red ramp) can never misread whether they are under attack. This is a correctness requirement, not a nicety.
- **Reduced motion honored everywhere.** Every animation needs a `prefers-reduced-motion` alternative (crossfade or instant). Motion conveys state only — never decoration.
- **iOS Dynamic Type.** Text scales with the user's system setting; alert and countdown information must remain fully legible and never truncate at large sizes.
- **44×44pt minimum touch targets** (iOS HIG) — especially for the irreversible recovery-override action.
- **Stress-resilient legibility.** The alarm path must stay fully usable for someone anxious and rushed: large tap targets, an unmistakable primary action, and no time-sensitive micro-interactions that punish hesitation beyond the unavoidable 72-hour window itself.
- **VoiceOver.** Countdowns and urgency states must be announced meaningfully (not conveyed by a colored dot alone); the live-updating recovery deadline must be perceivable to screen-reader users.
