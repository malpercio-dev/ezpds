import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // clearScreen: false surfaces Rust compiler errors in the terminal instead of clearing them
  clearScreen: false,
  server: {
    // 5174 (not 5173) so this dev server can run alongside identity-wallet's.
    // Must match devUrl in src-tauri/tauri.conf.json.
    port: 5174,
    strictPort: true,
    // TAURI_DEV_HOST is set by `cargo tauri ios dev` to the machine's LAN IP;
    // the iOS simulator connects to the dev server over LAN, not localhost.
    // Falls back to 'localhost' (not '0.0.0.0') so standalone `pnpm dev` doesn't expose to the LAN.
    host: process.env.TAURI_DEV_HOST || 'localhost',
    hmr: process.env.TAURI_DEV_HOST
      ? {
          protocol: 'ws',
          host: process.env.TAURI_DEV_HOST,
          port: 5174,
        }
      : undefined,
  },
  // Expose VITE_* and TAURI_ENV_* environment variables to the frontend
  envPrefix: ['VITE_', 'TAURI_ENV_'],
});
