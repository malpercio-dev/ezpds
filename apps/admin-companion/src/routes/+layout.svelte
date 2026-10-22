<script lang="ts">
  // Global design layer: fonts, tokens, then base element styles (order matters).
  import '$lib/styles/fonts.css';
  import '$lib/styles/tokens.css';
  import '$lib/styles/base.css';
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { listen } from '@tauri-apps/api/event';
  import { listPairings, takePendingNotificationRoute, NOTIFICATION_ROUTE_EVENT } from '$lib/ipc';
  import { notificationHref } from '$lib/notification-route';

  let { children }: { children: Snippet } = $props();

  // Notification-tap routing. A tapped operator alert can launch the app cold or
  // foreground it warm; the iOS tap handler parks the route either way and emits
  // `notification_route` for the warm case. Both paths read through take() — never the
  // event payload — so a route the mount-time drain already consumed is gone and one tap
  // can never navigate twice. The route only picks which pairing's screen to open
  // ($lib/notification-route); the screen fetches what it shows as usual.
  async function followPendingRoute() {
    const route = await takePendingNotificationRoute();
    if (!route) return;
    const href = notificationHref(route, (await listPairings()).pairings);
    if (href) await goto(href);
  }

  onMount(() => {
    void followPendingRoute().catch((e) =>
      console.warn('draining the pending notification route failed:', e),
    );
    // Not awaited and no cleanup returned: Svelte 5's onMount ignores an async return,
    // and the root layout never unmounts, so the listener lives as long as the app.
    void listen(NOTIFICATION_ROUTE_EVENT, () => {
      void followPendingRoute().catch((e) =>
        console.warn('handling a notification route event failed:', e),
      );
    });
  });
</script>

{@render children()}
