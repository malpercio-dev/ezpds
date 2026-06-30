/**
 * Share text via the native iOS Share Pane.
 *
 * Mobile-only: the plugin (`@buildyourwebapp/tauri-plugin-sharesheet`) is imported
 * dynamically so the host/desktop build never resolves it. Returns whether the share sheet
 * actually opened — `false` off-device (desktop dev / host build), so the caller can fall
 * back to copy-only rather than appearing broken.
 */
export async function shareText(text: string): Promise<boolean> {
  try {
    const { shareText: share } = await import('@buildyourwebapp/tauri-plugin-sharesheet');
    await share(text);
    return true;
  } catch {
    // No plugin (desktop/host) or the user dismissed the sheet — copy remains the path.
    return false;
  }
}
