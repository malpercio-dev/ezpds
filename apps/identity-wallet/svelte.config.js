import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      // fallback: 'index.html' routes unmatched paths to index for client-side navigation (SPA mode)
      fallback: 'index.html',
      // pages: 'dist' matches tauri.conf.json frontendDist: "../dist" (configured in Phase 2)
      // Note: adapter-static 3.x uses 'pages' instead of 'out'
      pages: 'dist',
    }),
  },
};

export default config;
