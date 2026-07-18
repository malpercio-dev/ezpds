import { invoke } from '@tauri-apps/api/core';

// ── Diagnostics ───────────────────────────────────────────────────────────────

/**
 * Render the in-app, in-memory network-error breadcrumb log as plain text for the user
 * to share (via the native share sheet) when troubleshooting.
 *
 * Redacted by construction on the Rust side: the report carries operation names, server
 * hostnames, HTTP statuses, and short error codes only — never tokens, request/response
 * bodies, handles, emails, or DIDs. Nothing is persisted; the log lives for the current
 * app session, and the user initiates every export, so there is no passive collection.
 */
export const exportDiagnostics = (): Promise<string> => invoke('export_diagnostics');
