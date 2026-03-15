import { invoke } from '@tauri-apps/api/core';

export const greet = (name: string): Promise<string> =>
  invoke('greet', { name });
