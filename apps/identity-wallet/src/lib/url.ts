/**
 * The host (with port when present) of a URL, for display — "bsky.social",
 * not "https://bsky.social". Falls back to the raw (trimmed) string when the
 * value does not parse as a URL, so a broken input reads as itself rather than
 * vanishing.
 *
 * The admin-companion app carries its own copy in `$lib/server-identity.ts`:
 * the two apps are deliberately separate products (distinct bundle ids and
 * Keychain namespaces), so this display helper is duplicated by value rather
 * than shared through a workspace package.
 */
export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url.trim();
  }
}
