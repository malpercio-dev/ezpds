/**
 * Typed wrappers for all Tauri IPC commands.
 *
 * This is the ONLY file that calls `invoke()` directly; page components import
 * these functions instead. Mirrors the identity-wallet `ipc.ts` convention.
 *
 * Adds the pairing + signed-request surface on top of the device-key primitives.
 */
import { invoke } from '@tauri-apps/api/core';

/** The device's admin public key, as returned by the Rust backend. */
export interface DevicePublicKey {
  /** Multibase base58btc-encoded compressed P-256 point ('z'…). */
  multibase: string;
  /** Full did:key URI ('did:key:z…'). */
  keyId: string;
}

/** Tagged error from device-key operations: `{ code: "SCREAMING_SNAKE_CASE" }`. */
export interface DeviceKeyError {
  code:
    | 'KEY_GENERATION_FAILED'
    | 'KEY_NOT_FOUND'
    | 'SIGNING_FAILED'
    | 'INVALID_SIGNATURE'
    | 'KEYCHAIN_ERROR';
  message?: string;
}

/**
 * Tagged error from the relay client: `{ code, … }`. The distinct codes let the UI
 * render honest, specific states rather than one generic failure.
 */
export type RelayClientError =
  | { code: 'NOT_PAIRED' }
  | { code: 'DEVICE_KEY'; message: string }
  | { code: 'KEYCHAIN'; message: string }
  | { code: 'INVALID_RELAY_URL' }
  | { code: 'UNREACHABLE'; message: string }
  | { code: 'RELAY_REJECTED'; status: number; message: string }
  | { code: 'BAD_RESPONSE'; message: string }
  | { code: 'NO_SUCH_PAIRING' }
  | { code: 'SELF_REVOKE_NOT_ALLOWED' };

/** One stored relay pairing. `id` is the stable local handle (a UUID minted at pair
 * time); `deviceId` is relay-assigned and changes on re-pair. `nickname` is the
 * operator's local display name and never leaves the device. */
export interface Pairing {
  id: string;
  nickname: string;
  relayUrl: string;
  deviceId: string;
  deviceLabel: string;
}

/** Every stored pairing plus the active selection (`null` when nothing is selected —
 * fresh install, or the active entry was removed with two or more remaining). */
export interface PairingsState {
  active: string | null;
  pairings: Pairing[];
}

/**
 * Get-or-create this device's admin key (Secure Enclave on a real device,
 * software key on the simulator/macOS). Idempotent.
 */
export function getOrCreateDeviceKey(): Promise<DevicePublicKey> {
  return invoke<DevicePublicKey>('get_or_create_device_key');
}

/**
 * Pair this device with `relayUrl` by claiming `pairingCode`. Persists the
 * relay-assigned device id and returns it. Throws a {@link RelayClientError}.
 */
export async function pairDevice(
  relayUrl: string,
  pairingCode: string,
  label: string,
  nickname: string,
): Promise<string> {
  return invoke<string>('pair_device', { relayUrl, pairingCode, label, nickname });
}

/** All stored pairings and the active selection. */
export async function listPairings(): Promise<PairingsState> {
  return invoke<PairingsState>('list_pairings');
}

/** Set the active pairing by id. */
export async function setActivePairing(id: string): Promise<void> {
  return invoke('set_active_pairing', { id });
}

/** Rename a pairing locally by id. */
export async function renamePairing(id: string, nickname: string): Promise<void> {
  return invoke('rename_pairing', { id, nickname });
}

/** Mint a single account claim code via a signed request to the paired relay. */
export function generateClaimCode(): Promise<string> {
  return invoke<string>('generate_claim_code');
}

/**
 * Revoke this device on the relay (a signed self-revoke), then forget the pairing
 * locally. Throws a {@link RelayClientError} if the relay can't be reached or rejects the
 * request — in which case the pairing is left intact so the caller can retry or fall back
 * to {@link unpair}.
 */
export async function revokeSelf(id: string): Promise<void> {
  return invoke('revoke_self', { id });
}

/**
 * Forget a pairing locally **without** contacting the relay — the fallback when
 * {@link revokeSelf} can't reach the relay. The credential stays valid server-side.
 */
export async function unpair(id: string): Promise<void> {
  return invoke('unpair', { id });
}

/**
 * One registered companion device on a relay, as the relay reports it. `id` is the
 * relay-assigned registration id — the row where it equals a pairing's `deviceId` is
 * the device in your hand. Timestamps are the relay's SQLite UTC datetime strings.
 */
export interface AdminDevice {
  id: string;
  label: string;
  /** The device's P-256 public key as a did:key URI. */
  publicKey: string;
  platform: string;
  scopes: string;
  /** Derived server-side: 'active' while revokedAt is null, 'revoked' once stamped. */
  status: 'active' | 'revoked';
  createdAt: string;
  lastSeenAt: string | null;
  revokedAt: string | null;
}

/**
 * List every device registered on the given pairing's relay — active and revoked,
 * newest first — via a signed request. Throws a {@link RelayClientError}.
 */
export function listAdminDevices(pairingId: string): Promise<AdminDevice[]> {
  return invoke<AdminDevice[]>('list_admin_devices', { pairingId });
}

/**
 * Revoke another device's registration on the given pairing's relay — the loss
 * response. Refused for the pairing's own registration (`SELF_REVOKE_NOT_ALLOWED`);
 * self-revoke is {@link revokeSelf}, which also forgets the pairing locally. Returns
 * the device's post-revoke state.
 */
export function revokeAdminDevice(pairingId: string, deviceId: string): Promise<AdminDevice> {
  return invoke<AdminDevice>('revoke_admin_device', { pairingId, deviceId });
}

/**
 * An account's takedown status as the relay reports it — the response shape of both
 * getSubjectStatus and updateSubjectStatus. `$type` is always the account-level
 * `com.atproto.admin.defs#repoRef`; ezpds models no record- or blob-level takedown.
 */
export interface SubjectStatus {
  subject: {
    $type: string;
    did: string;
  };
  takedown: {
    applied: boolean;
  };
}

/**
 * Report an account's takedown status from the given pairing's relay via a signed
 * request. An unknown DID is `RELAY_REJECTED` with status 404; a malformed DID is
 * status 400. Throws a {@link RelayClientError}.
 */
export function getSubjectStatus(pairingId: string, did: string): Promise<SubjectStatus> {
  return invoke<SubjectStatus>('get_subject_status', { pairingId, did });
}

/**
 * Apply (`applied = true`) or clear (`false`) an account-level takedown on the given
 * pairing's relay via a signed request. Idempotent server-side; returns the resulting
 * takedown state. This signs — callers must run the biometric gate first.
 */
export function updateSubjectStatus(
  pairingId: string,
  did: string,
  applied: boolean,
): Promise<SubjectStatus> {
  return invoke<SubjectStatus>('update_subject_status', { pairingId, did, applied });
}

/**
 * An account's usage metrics as the relay reports them — the response shape of
 * `GET /v1/accounts/{did}/usage`. `commitsCount` is a lower bound (GC reclaims
 * superseded blocks); `lastActive` falls back to the account's creation time.
 */
export interface AccountUsage {
  recordsCount: number;
  commitsCount: number;
  blobsCount: number;
  storageBytes: number;
  lastActive: string;
}

/**
 * An account's blob-storage metrics as the relay reports them — the response shape of
 * `GET /v1/accounts/{did}/storage`. `largestBlob` is null for a blobless account.
 */
export interface AccountStorage {
  blobCount: number;
  totalBytes: number;
  quotaBytes: number;
  quotaUsedPct: number;
  largestBlob: { cid: string; size: number } | null;
}

/**
 * Fetch an account's usage metrics from the given pairing's relay via a signed
 * request. An unknown DID is `RELAY_REJECTED` with status 404. Throws a
 * {@link RelayClientError}.
 */
export function getAccountUsage(pairingId: string, did: string): Promise<AccountUsage> {
  return invoke<AccountUsage>('get_account_usage', { pairingId, did });
}

/**
 * Fetch an account's blob-storage metrics from the given pairing's relay via a signed
 * request. Same error surface as {@link getAccountUsage}.
 */
export function getAccountStorage(pairingId: string, did: string): Promise<AccountStorage> {
  return invoke<AccountStorage>('get_account_storage', { pairingId, did });
}

/**
 * The relay's server-health readout — the response shape of `GET /v1/admin/health`.
 * Literal facts only: the relay derives no ok/warn verdicts, so any staleness or
 * threshold judgment belongs to the screen (or the operator).
 */
export interface ServerHealth {
  version: string;
  uptimeSeconds: number;
  /** Derived-lifecycle buckets; the four non-total buckets partition `total` exactly. */
  accounts: {
    total: number;
    active: number;
    deactivated: number;
    suspended: number;
    takendown: number;
    /**
     * Accounts carrying at least one in-force label from a watched labeler — the
     * flagged badge count. Orthogonal to the lifecycle buckets; always 0 when the
     * relay watches no labelers.
     */
    flagged: number;
  };
  /** Physical rows: blobs are shared across owners and counted (and summed) once. */
  storage: {
    blobCount: number;
    blobBytes: number;
    blockCount: number;
  };
  firehose: {
    /** Highest sequenced event; 0 before the first event ever. */
    currentSeq: number;
    /** Currently connected subscribeRepos WebSocket subscribers. */
    subscribers: number;
    /** Retained event-log rows — the replayable backlog. */
    retainedEvents: number;
    /** Age in seconds of the oldest retained event; null when the log is empty. */
    backfillWindowSeconds: number | null;
  };
  /**
   * Last completed pass per background sweep; null until that sweep's first completed
   * pass after boot (each first runs one full interval after startup). A failed pass
   * records nothing, so a stale `completedAt` — not an error field — is the signal
   * that passes are not completing.
   */
  sweeps: {
    blobGc: SweepRun | null;
    firehoseGc: SweepRun | null;
    accountReaper: SweepRun | null;
    agentClaimSweep: SweepRun | null;
  };
}

/** One completed sweep pass: unix seconds + items acted on. */
export interface SweepRun {
  completedAt: number;
  swept: number;
}

/**
 * Fetch the relay's server-health readout from the given pairing's relay via a signed
 * request — the Status screen's data source. Throws a {@link RelayClientError}.
 */
export function getServerHealth(pairingId: string): Promise<ServerHealth> {
  return invoke<ServerHealth>('get_server_health', { pairingId });
}

/** The relay's lifecycle status for us, as reported by `com.atproto.sync.getHostStatus`. */
export type RelayHostStatus = 'active' | 'idle' | 'offline' | 'throttled' | 'banned';

/**
 * The relay-status readout — the response shape of `GET /v1/admin/relay-status`. Is the
 * upstream relay actually crawling/indexing us? Literal facts only: the relay derives no
 * ok/warn/behind verdict, so the gap thresholds live in the block that renders this.
 */
export interface RelayStatus {
  /** The relay we queried (first configured crawler), bare host; null when none configured. */
  relayHost: string | null;
  /** Whether the relay answered at all. A `HostNotFound` still counts as reachable. */
  reachable: boolean;
  /** The relay's lifecycle status for us (verbatim; may be an unknown value from a newer relay). */
  relayStatus: RelayHostStatus | (string & {}) | null;
  /** The relay's cursor into our firehose seq-space; null when unavailable. */
  relaySeq: number | null;
  /** How many of our accounts the relay has indexed; null when unavailable. */
  accountCount: number | null;
  /** Our exact sequencer head (0 before the first event). */
  pdsHeadSeq: number;
  /** `pdsHeadSeq − relaySeq` (positive = relay behind); signed, null when `relaySeq` is unknown. */
  gap: number | null;
  /** The `sequenced_at` of our event at `relaySeq` ("caught up as of / not seen since T"). */
  relayCursorAt: string | null;
  /** A short reason when unreachable or not-crawled; null on success. */
  detail: string | null;
  /** When this readout polled the relay (RFC 3339). */
  checkedAt: string;
}

/**
 * Fetch the relay-status readout from the given pairing's relay via a signed request — the
 * Home relay-status block's data source. Throws a {@link RelayClientError}.
 */
export function getRelayStatus(pairingId: string): Promise<RelayStatus> {
  return invoke<RelayStatus>('get_relay_status', { pairingId });
}

/** One relay's outcome in a request-crawl action. */
export interface RelayCrawlAttempt {
  /** The crawler host (bare, scheme stripped) the request targeted. */
  host: string;
  /** Whether the crawler accepted the `requestCrawl`. */
  accepted: boolean;
  /** A short reason when `accepted` is false; null on success. */
  detail: string | null;
}

/** The result of the request-crawl action — the response shape of `POST /v1/admin/request-crawl`. */
export interface RequestCrawlResult {
  /** How many relays the request was sent to. */
  requested: number;
  /** How many accepted the `requestCrawl`. */
  accepted: number;
  /** Per-relay outcomes, in configuration order. */
  relays: RelayCrawlAttempt[];
}

/**
 * Ask the given pairing's relay to crawl this PDS now via a signed request — the "Request
 * crawl" action. This signs, so the caller must run the biometric gate first. Throws a
 * {@link RelayClientError}.
 */
export function requestCrawl(pairingId: string): Promise<RequestCrawlResult> {
  return invoke<RequestCrawlResult>('request_crawl', { pairingId });
}

/**
 * One account row of the relay's operator account list — the response shape of
 * `GET /v1/admin/accounts`. `status` is the derived lifecycle, always stated
 * explicitly; `quotaUsedPct` is `totalBytes` against the page-level `quotaBytes`.
 */
export interface AccountListEntry {
  did: string;
  /** The account's first-created handle, or null when it has none. */
  handle: string | null;
  createdAt: string;
  status: 'active' | 'deactivated' | 'suspended' | 'takendown';
  totalBytes: number;
  quotaUsedPct: number;
  /**
   * Labels currently in force from the relay's watched labelers, newest first.
   * Empty for an unflagged account (and always empty when labeler watching is off).
   */
  flags: AccountFlag[];
}

/** One in-force label on an account, observed by the relay from a watched labeler. */
export interface AccountFlag {
  /** The label value (e.g. `spam`, `!hide`). */
  val: string;
  /** DID of the labeler that applied the label. */
  labelerDid: string;
  /** The labeler's label-creation timestamp. */
  cts: string;
}

/**
 * A page of the account list — flagged accounts first, DID order within each group.
 * `cursor` is null on the last page.
 */
export interface AccountList {
  accounts: AccountListEntry[];
  /** The configured per-account storage quota in bytes — one value for every row. */
  quotaBytes: number;
  /**
   * Accounts matching the current filters that carry at least one flag — stated per
   * response because flagged accounts can sit on later pages.
   */
  flaggedTotal: number;
  cursor: string | null;
}

/** Optional filters for {@link listAccounts}. */
export interface ListAccountsFilters {
  limit?: number;
  /** The opaque `cursor` from the previous page. */
  cursor?: string;
  /** Derived-lifecycle filter. */
  status?: AccountListEntry['status'];
  /** Literal substring match against the DID or any of the account's handles. */
  q?: string;
}

/**
 * Fetch a page of the relay's account list (flagged accounts first, then DID order,
 * cursor pagination) from the given pairing's relay via a signed request. Throws a
 * {@link RelayClientError}.
 */
export function listAccounts(
  pairingId: string,
  filters: ListAccountsFilters = {},
): Promise<AccountList> {
  return invoke<AccountList>('list_accounts', {
    pairingId,
    limit: filters.limit ?? null,
    cursor: filters.cursor ?? null,
    status: filters.status ?? null,
    q: filters.q ?? null,
  });
}

/**
 * One claim code in the relay's inventory, as the relay reports it. Status is derived
 * server-side; the terminal events win over the clock — a redeemed or revoked code
 * never reports 'expired', even once `expiresAt` passes. Timestamps are the relay's
 * SQLite UTC datetime strings; `redeemedAt`/`revokedAt` are absent until that
 * transition happens.
 */
export interface ClaimCodeEntry {
  code: string;
  status: 'pending' | 'redeemed' | 'expired' | 'revoked';
  createdAt: string;
  expiresAt: string;
  redeemedAt?: string;
  revokedAt?: string;
}

/** One inventory page: newest-first entries plus the cursor for the next page. */
export interface ClaimCodeInventory {
  codes: ClaimCodeEntry[];
  /** Present when another page may exist; pass back to {@link listClaimCodes}. */
  cursor?: string;
}

/** The relay's post-revoke report. */
export interface RevokedClaimCode {
  code: string;
  status: string;
}

/**
 * Page the claim-code inventory from the given pairing's relay via a signed request —
 * every minted code with its derived lifecycle status, newest first. A
 * minted-but-unredeemed code is a live signup credential; this is the operator's view
 * of what is outstanding. Throws a {@link RelayClientError}.
 */
export function listClaimCodes(
  pairingId: string,
  cursor?: string,
): Promise<ClaimCodeInventory> {
  return invoke<ClaimCodeInventory>('list_claim_codes', { pairingId, cursor: cursor ?? null });
}

/**
 * Revoke a claim code on the given pairing's relay via a signed request — kill a
 * minted-but-unredeemed signup credential. Idempotent for an already-revoked code; a
 * redeemed code is `RELAY_REJECTED` with status 409 (nothing live to kill), an unknown
 * code with 404. This signs — callers must run the biometric gate first.
 */
export function revokeClaimCode(pairingId: string, code: string): Promise<RevokedClaimCode> {
  return invoke<RevokedClaimCode>('revoke_claim_code', { pairingId, code });
}

/**
 * One server-wide admin audit event as the relay reports it: a privileged admin action
 * attributed to the credential that signed it. `actor` is `master-token`, `device:<id>`,
 * or `pairing-code` (device enrollment — the acting credential is the consumed pairing
 * code). `subject` is the acted-on entity (account DID, admin-device id, transfer id,
 * claim code), absent for server-wide actions; `detail` is a JSON object of mechanical
 * facts (counts, resulting status), absent when the action carries none. `createdAt` is
 * the relay's SQLite UTC datetime string.
 */
export interface AuditEventEntry {
  id: string;
  actor: string;
  action: string;
  subject: string | null;
  outcome: string;
  detail: Record<string, unknown> | null;
  createdAt: string;
}

/** One audit-log page: newest-first events plus the cursor for the next page. */
export interface AuditPage {
  events: AuditEventEntry[];
  /** Present when another page may exist; pass back to {@link listAudit}. */
  cursor: string | null;
}

/** Optional filters for {@link listAudit}. */
export interface ListAuditFilters {
  limit?: number;
  /** The `cursor` from the previous page. */
  cursor?: string;
  /** Exact-match action filter (one of the relay's action words); unknown → 400. */
  action?: string;
  /** Exact-match actor filter (`master-token`, `device:<id>`, `pairing-code`). */
  actor?: string;
  /** Exact-match subject filter (account DID, admin-device id, transfer id, code). */
  subject?: string;
}

/**
 * Page the server-wide admin audit log from the given pairing's relay via a signed
 * request — every privileged admin action, newest first, attributed to the credential
 * that signed it. Reads only, no biometric gate. Throws a {@link RelayClientError}.
 */
export function listAudit(pairingId: string, filters: ListAuditFilters = {}): Promise<AuditPage> {
  return invoke<AuditPage>('list_audit', {
    pairingId,
    limit: filters.limit ?? null,
    cursor: filters.cursor ?? null,
    action: filters.action ?? null,
    actor: filters.actor ?? null,
    subject: filters.subject ?? null,
  });
}

/**
 * One in-flight device transfer as the relay reports it — a planned device swap that
 * can still advance. `status` is the stored state-machine state; an `accepted` or
 * `completing` transfer means the target device already holds a working credential.
 * Deliberately code-free: the transfer code is a live account-takeover credential and
 * never leaves the relay. Timestamps are the relay's SQLite UTC datetime strings.
 */
export interface TransferEntry {
  id: string;
  did: string;
  handle?: string;
  status: 'pending' | 'accepted' | 'completing';
  createdAt: string;
  expiresAt: string;
  acceptedAt?: string;
  acceptedDevicePlatform?: string;
}

/** One in-flight transfer page: newest-first entries plus the cursor for the next page. */
export interface TransferList {
  transfers: TransferEntry[];
  /** Present when another page may exist; pass back to {@link listTransfers}. */
  cursor?: string;
}

/** The relay's post-cancel report. */
export interface CancelledTransfer {
  id: string;
  status: string;
  /** Whether an accepted target device credential was tombstoned by this cancel. */
  revokedDeviceCredential: boolean;
}

/**
 * Page the in-flight device transfers on the given pairing's relay via a signed
 * request — every planned device swap that can still advance (a security-relevant
 * pending state the operator may need to interrupt), newest first. Throws a
 * {@link RelayClientError}.
 */
export function listTransfers(pairingId: string, cursor?: string): Promise<TransferList> {
  return invoke<TransferList>('list_transfers', { pairingId, cursor: cursor ?? null });
}

/**
 * Cancel an in-flight device transfer on the given pairing's relay via a signed
 * request. The relay flips the transfer to the terminal `cancelled` state and
 * tombstones the accepted target device credential if the swap got that far; the
 * account's existing sessions are untouched (compose with
 * {@link revokeAccountCredentials} when the account itself is compromised). A repeat
 * cancel is an idempotent 200; a completed or expired transfer is `RELAY_REJECTED`
 * with status 409, an unknown id with 404. This signs — callers must run the
 * biometric gate first.
 */
export function cancelTransfer(
  pairingId: string,
  transferId: string,
): Promise<CancelledTransfer> {
  return invoke<CancelledTransfer>('cancel_transfer', { pairingId, transferId });
}

/**
 * The relay's post-sweep report — literal per-family counts of what
 * {@link revokeAccountCredentials} revoked, rendered verbatim by the screen.
 */
export interface RevokedCredentials {
  /** Session rows deleted (each session's refresh tokens go with it). */
  sessionsRevoked: number;
  /** App-password credentials deleted; new logins with them fail immediately. */
  appPasswordsRevoked: number;
  /** OAuth refresh-token grants deleted. */
  oauthTokensRevoked: number;
  /** Pending (unexchanged) OAuth authorization codes deleted. */
  oauthCodesRevoked: number;
  /** Promoted transfer-device tokens tombstoned. */
  transferDeviceTokensRevoked: number;
}

/**
 * Revoke every credential of an account on the given pairing's relay — the operator
 * kill-switch for a compromised account: sessions (and their refresh tokens), app
 * passwords, OAuth grants and pending codes, and promoted transfer-device tokens. The
 * account's main password is untouched (the owner's recovery path), and already-minted
 * access tokens expire on their own within minutes. Idempotent: a repeat sweep reports
 * zero counts. An unknown DID is `RELAY_REJECTED` with status 404. This signs —
 * callers must run the biometric gate first.
 */
export function revokeAccountCredentials(
  pairingId: string,
  did: string,
): Promise<RevokedCredentials> {
  return invoke<RevokedCredentials>('revoke_account_credentials', { pairingId, did });
}

export interface RepairedEmail {
  did: string;
  email: string;
  emailConfirmed: false;
}

export function setAccountEmail(
  pairingId: string,
  did: string,
  email: string,
): Promise<RepairedEmail> {
  return invoke<RepairedEmail>('set_account_email', { pairingId, did, email });
}

export interface IssuedResetToken {
  did: string;
  token: string;
  expiresIn: number;
}

export function issueResetToken(
  pairingId: string,
  did: string,
): Promise<IssuedResetToken> {
  return invoke<IssuedResetToken>('issue_reset_token', { pairingId, did });
}

/** Whether the biometric (user-presence) gate on signing actions is enabled (default on). */
export function biometricEnabled(): Promise<boolean> {
  return invoke<boolean>('biometric_enabled');
}

/** Persist the biometric-gate preference (the Settings toggle). */
export function setBiometricEnabled(enabled: boolean): Promise<void> {
  return invoke('set_biometric_enabled', { enabled });
}

/**
 * Scan a QR code with the device camera (real iOS device only; unavailable on the
 * simulator/desktop, where the manual-entry fields are used instead). Returns the
 * raw decoded string. Dynamically imports the mobile-only plugin so the web/host
 * build never resolves it.
 */
export async function scanQrCode(): Promise<string> {
  const { scan, Format } = await import('@tauri-apps/plugin-barcode-scanner');
  const result = await scan({ windowed: true, formats: [Format.QRCode] });
  return result.content;
}

/**
 * Stop an in-progress {@link scanQrCode}. The pending `scan()` settles, so its
 * caller's `finally` runs and scan mode tears down. Mobile-only and best-effort:
 * off-device the plugin isn't present, so callers should ignore a rejection.
 */
export async function cancelQrScan(): Promise<void> {
  const { cancel } = await import('@tauri-apps/plugin-barcode-scanner');
  await cancel();
}
