import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  server: {
    port: 5173,
    strictPort: true,
    // host: '0.0.0.0' allows the iOS simulator to reach this dev server over LAN
    host: '0.0.0.0',
  },
});
