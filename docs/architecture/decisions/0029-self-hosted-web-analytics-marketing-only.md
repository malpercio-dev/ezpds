# ADR-0029: Self-hosted, cookieless web analytics on public web surfaces only

- **Status:** Accepted
- **Date:** 2026-07-18
- **Deciders:** malpercio
- **Related:** ADR-0028 (OTel-native backend observability), `sites/marketing/`, `sites/docs/`, `PRODUCT.md` / `DESIGN.md` (practice-what-you-preach)

## Context

Three telemetry planes are now in view, and they answer different questions:

- **Backend observability** — *is the system healthy, why did a request fail* — is OTel (ADR-0028).
- **Client error capture** — *what broke for a user* — is the wallet's user-initiated,
  redacted diagnostics export.
- **Product / web analytics** — *are people finding us, which pages convert, what gets
  used* — is untouched. Nothing above measures traffic, referrers, or conversion.

There is **no web analytics on any surface today**, and the docs site's config carries a
deliberate note: *"Self-hosted repo link only; no third-party analytics or CDN scripts."*
The public web surfaces are `sites/marketing/` (zero-build static HTML, Caddy-served on its
own Railway service; `index.html` + `custos/index.html`) and `sites/docs/` (Starlight).

The tension: the marketing site would benefit from real growth signal (traffic, referrers,
signup/download conversion), but the product sells **sovereign, privacy-respecting
identity** — so conventional analytics (Google Analytics) would both put visitor data on a
third party and *contradict the pitch*. And whatever we adopt must not creep onto the
mobile apps or auth surfaces, where ADR-0028 already drew the line against passive
telemetry from account/PII contexts.

## Decision

We will run **self-hosted, cookieless, no-PII web analytics** (Umami — or an equivalent
self-hosted cookieless tool such as Plausible) and mount it on the **public marketing site
only**, by default. IP-anonymized, no cookies, no cross-site identifiers. It deploys as its
own Railway service (the analytics app plus its database), reached like the other services.

The boundaries are the load-bearing part of this decision:

- **Yes — `sites/marketing/`** (primary). A short privacy note on the site discloses the
  cookieless, self-hosted analytics.
- **Docs (`sites/docs/`) is a *separate, explicit* opt-in.** Its "no third-party scripts"
  stance is deliberate; enabling analytics there is its own decision, not implied here.
- **No — the mobile apps (Obsign, admin-companion).** Analytics from a field device is
  passive telemetry with a public ingest endpoint and an opt-in/privacy surface — the exact
  line ADR-0028 drew — and Umami is *web* analytics, the wrong tool for app product-analytics
  regardless. In-app product analytics, if ever wanted, is a separate PostHog-class decision.
- **No — the PDS backend.** OTel owns operational telemetry (ADR-0028); analytics adds
  nothing there.
- **No — any account/PII or auth surface.** The PDS landing page and the OAuth
  `authorize`/consent pages are never instrumented. Instrumenting an auth flow is a privacy
  anti-pattern regardless of vendor.

## Consequences

- **Unlocks:** growth / traffic / conversion signal for the marketing site with no third
  party holding visitor data. Self-hosted + cookieless is *on-brand* — it reinforces the
  sovereign-privacy pitch rather than undercutting it (the "practice the assurance you
  preach" line the design briefs draw).
- **Costs / risks accepted:** another Railway service plus its own database to run, back up,
  and secure. The surface boundary is the whole point, and **drift is the risk** — the
  failure mode is someone later dropping a tracker onto the app or an auth page. Keep it
  cookieless and IP-anonymized; a privacy-policy line is now owed on the marketing site.
- **Follow-on:** an issue to stand up the Umami service, wire the marketing snippet (a
  one-line `<script>` add once the instance URL + website-id exist), and add the privacy
  note in the footer.
- **Relationship to ADR-0028:** these are three distinct, complementary planes — operational
  observability, client error export, and public-web analytics — each self-hosted, each with
  an explicit surface boundary. None overlaps another.

## Alternatives considered

- **Google Analytics / other SaaS analytics.** Rejected: puts visitor data on a third party
  and directly contradicts the sovereign-privacy pitch; cookies and cross-site tracking are
  the opposite of what the product sells.
- **No analytics at all.** Rejected: leaves the marketing site with zero growth or
  conversion signal. Self-hosted cookieless analytics gives that signal at no privacy cost,
  so abstaining buys nothing the "no third-party scripts" posture doesn't already get from
  *self-hosting*.
- **Fold analytics into the OTel backend.** Rejected as a category error: OTel is
  request/operational telemetry; web analytics (sessions, referrers, funnels) is a different
  data model and UX, and no self-hosted tool does both well. They stay separate planes.
- **PostHog (self-hosted).** Considered: does product analytics, session replay, and more,
  but is heavier to run, and its strength is the in-app product analytics we've explicitly
  deferred. Umami/Plausible are the right-sized fit for a static marketing site; revisit
  PostHog only if in-app product analytics is later wanted.
