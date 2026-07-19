// Camera QR scanning for the wallet-confirmed OAuth consent scan path (Phase B). These are the
// mobile-only `@tauri-apps/plugin-barcode-scanner` bindings, dynamically imported so the web/host
// build never resolves the plugin (it exists only on iOS/Android). Off-device (desktop/simulator
// with no camera) the import or the scan rejects, and the consent screen falls back to the typed
// code — the guaranteed path.

/**
 * Scan a QR code with the device camera (real iOS device only). Returns the raw decoded string; the
 * caller parses out the pending request's `request_id` (see `$lib/consent-qr`). Rejects off-device
 * or when camera permission is denied — the caller treats a rejection as "use the typed code".
 */
export async function scanQrCode(): Promise<string> {
  const { scan, Format } = await import('@tauri-apps/plugin-barcode-scanner');
  const result = await scan({ windowed: true, formats: [Format.QRCode] });
  return result.content;
}

/**
 * Stop an in-progress {@link scanQrCode}. The pending `scan()` settles so its caller's `finally`
 * runs and scan mode tears down. Mobile-only and best-effort: off-device the plugin isn't present,
 * so callers should ignore a rejection.
 */
export async function cancelQrScan(): Promise<void> {
  const { cancel } = await import('@tauri-apps/plugin-barcode-scanner');
  await cancel();
}
