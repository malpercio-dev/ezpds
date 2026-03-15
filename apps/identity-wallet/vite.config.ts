import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // clearScreen: false surfaces Rust compiler errors in the terminal instead of clearing them
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    // TAURI_DEV_HOST is set by `cargo tauri ios dev` to the machine's LAN IP;
    // the iOS simulator connects to the dev server over LAN, not localhost
    host: process.env.TAURI_DEV_HOST || '0.0.0.0',
    hmr: process.env.TAURI_DEV_HOST
      ? {
          protocol: 'ws',
          host: process.env.TAURI_DEV_HOST,
          port: 5173,
        }
      : undefined,
  },
  // Expose VITE_* and TAURI_ENV_* environment variables to the frontend
  envPrefix: ['VITE_', 'TAURI_ENV_'],
});
