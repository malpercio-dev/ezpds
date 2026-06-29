// Disable SSR and prerendering globally — Tauri apps have no web server.
// The frontend runs entirely in WKWebView (iOS) and loads files from disk.
export const ssr = false;
export const prerender = false;
