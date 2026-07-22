// Shared, presentation-only helpers for rendering migration-progress error detail.
//
// MigrationError carries a `message` field for most codes, populated by the wallet's
// migration orchestrator with the real (often server-supplied) cause. MigrationProgressScreen's
// headline switch stays generic per code; this is the pure function that turns a
// BLOB_TRANSFER_FAILED message into detail attributed to the right side of the transfer. Pure
// string function (no Svelte, no IPC), matching the repo's tested-utility pattern (see
// claim-errors.ts).

import type { BlobLoss } from '$lib/ipc';

const FETCH_BLOB_PATTERN = /^failed to fetch blob (\S+): ([\s\S]+)$/;
const UPLOAD_BLOB_PATTERN = /^failed to upload blob (\S+): ([\s\S]+)$/;

/**
 * Turn a BLOB_TRANSFER_FAILED message into detail that names which side of the transfer failed.
 * Since the loss-manifest work, per-blob failures no longer arrive here — the drain records them as
 * structured `BlobLoss` (rendered by `describeBlobLoss`, below), and the only BLOB_TRANSFER_FAILED
 * message `drain_missing_blobs` still raises is the hard enumerate failure ("failed to list missing
 * blobs: {err}", no CID → falls through to the raw message). The two CID-bearing patterns below are
 * kept as a defensive parser for any "failed to fetch blob {cid}: {err}" (source-side) or
 * "failed to upload blob {cid}: {err}" (destination-side) shape.
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

/**
 * Render one entry of a BLOB_DRAIN_INCOMPLETE loss manifest as human-readable detail, attributing
 * the failure to the right side of the transfer — the structured twin of `describeBlobTransferDetail`
 * (`source` = the previous server couldn't serve it; `destination` = the new server refused it).
 */
export function describeBlobLoss(loss: BlobLoss): string {
  const side =
    loss.direction === 'source'
      ? 'Your previous server could not provide it'
      : 'Your new server refused it';
  const reason = loss.reason.trim();
  return reason.length > 0 ? `${side}: ${reason}` : side;
}
