/** Open the native iOS share sheet, falling back to the clipboard on host builds. */
export async function shareDidDocument(text: string): Promise<void> {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('plugin:sharesheet|share_text', { text });
  } catch {
    await navigator.clipboard.writeText(text);
  }
}
