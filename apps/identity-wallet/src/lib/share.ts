/** Open the native iOS share sheet, falling back to the clipboard on host builds. */
export async function shareDidDocument(text: string): Promise<void> {
  try {
    const { shareText } = await import('@buildyourwebapp/tauri-plugin-sharesheet');
    await shareText(text);
  } catch {
    await navigator.clipboard.writeText(text);
  }
}
