import { shareTextNative } from '$lib/ipc';

/** Open the native iOS share sheet, falling back to the clipboard on host builds. */
export async function shareDidDocument(text: string): Promise<void> {
  try {
    await shareTextNative(text);
  } catch {
    await navigator.clipboard.writeText(text);
  }
}
