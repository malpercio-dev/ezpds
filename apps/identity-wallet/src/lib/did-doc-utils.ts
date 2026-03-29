/**
 * Utility functions for working with DID documents, especially PLC directory format.
 */

/**
 * Extracts the PDS (Personal Data Server) endpoint from a PLC directory format DID document.
 *
 * PLC documents store services as a map with keys like "atproto_pds", where the value
 * has an "endpoint" field containing the PDS URL.
 *
 * @param doc - The DID document (loosely typed Record)
 * @returns The PDS endpoint URL, or null if not found or invalid
 */
export function extractPdsFromPlcDoc(doc: Record<string, unknown>): string | null {
  const services = doc.services;
  if (typeof services !== 'object' || services === null) return null;

  const pds = (services as Record<string, unknown>).atproto_pds;
  if (typeof pds !== 'object' || pds === null) return null;

  const endpoint = (pds as Record<string, unknown>).endpoint;
  return typeof endpoint === 'string' ? endpoint : null;
}
