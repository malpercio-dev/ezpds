import { describe, it, expect } from 'vitest';
import { describeBlobTransferDetail } from './migration-errors';

describe('describeBlobTransferDetail', () => {
  it('attributes a fetch failure to the source (previous) server', () => {
    expect(describeBlobTransferDetail('failed to fetch blob bafkreiabc123: XRPC 500')).toBe(
      "Your previous server couldn't provide bafkreiabc123: XRPC 500",
    );
  });

  it('attributes an upload failure to the destination (new) server', () => {
    expect(describeBlobTransferDetail('failed to upload blob bafkreiabc123: XRPC 413')).toBe(
      'Your new server refused bafkreiabc123: XRPC 413',
    );
  });

  it('handles the harness-check message verbatim', () => {
    expect(describeBlobTransferDetail('failed to fetch blob bafkrei…: XRPC 500')).toBe(
      "Your previous server couldn't provide bafkrei…: XRPC 500",
    );
  });

  it('preserves a multi-part reason after the colon', () => {
    expect(
      describeBlobTransferDetail('failed to upload blob bafkreixyz: connection reset: timed out'),
    ).toBe('Your new server refused bafkreixyz: connection reset: timed out');
  });

  it('trims surrounding whitespace', () => {
    expect(describeBlobTransferDetail('  failed to fetch blob bafkreiabc: XRPC 500  ')).toBe(
      "Your previous server couldn't provide bafkreiabc: XRPC 500",
    );
  });

  it('falls back to the raw (trimmed) message for shapes it does not recognize', () => {
    expect(describeBlobTransferDetail('failed to list missing blobs: XRPC 500')).toBe(
      'failed to list missing blobs: XRPC 500',
    );
    expect(describeBlobTransferDetail('  something unexpected  ')).toBe('something unexpected');
  });
});
