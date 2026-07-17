// Shared, presentation-only helpers for rendering migration-progress error detail.
//
// MigrationError carries a `message` field for most codes, populated by the wallet's
// migration orchestrator with the real (often server-supplied) cause. MigrationProgressScreen's
// headline switch stays generic per code; this is the pure function that turns a
// BLOB_TRANSFER_FAILED message into detail attributed to the right side of the transfer. Pure
// string function (no Svelte, no IPC), matching the repo's tested-utility pattern (see
// claim-errors.ts).

const FETCH_BLOB_PATTERN = /^failed to fetch blob (\S+): ([\s\S]+)$/;
const UPLOAD_BLOB_PATTERN = /^failed to upload blob (\S+): ([\s\S]+)$/;

/**
 * Turn a BLOB_TRANSFER_FAILED message into detail that names which side of the transfer
 * failed. Matches the two per-blob failure shapes
 * `migration_orchestrator.rs::drain_missing_blobs` formats — "failed to fetch blob {cid}: {err}"
 * (source-side) and "failed to upload blob {cid}: {err}" (destination-side). Anything else
 * (e.g. the list-missing-blobs failure, which carries no CID) falls back to the raw message.
 */
export function describeBlobTransferDetail(message: string): string {
  const trimmed = message.trim();

  const fetchMatch = FETCH_BLOB_PATTERN.exec(trimmed);
  if (fetchMatch) {
    const [, cid, reason] = fetchMatch;
    return `Your previous server couldn't provide ${cid}: ${reason}`;
  }

  const uploadMatch = UPLOAD_BLOB_PATTERN.exec(trimmed);
  if (uploadMatch) {
    const [, cid, reason] = uploadMatch;
    return `Your new server refused ${cid}: ${reason}`;
  }

  return trimmed;
}
