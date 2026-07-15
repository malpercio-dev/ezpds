// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  // Canonical origin for the deployed docs service (mirrors the marketing
  // site's about.obsign.org). Only affects absolute URLs (sitemap, canonical,
  // Open Graph); the build is fully static and host-agnostic otherwise.
  site: 'https://docs.obsign.org',
  integrations: [
    starlight({
      title: 'Obsign & Custos Docs',
      description:
        'Documentation for Obsign (holding and defending your identity) and Custos (running a relay). Two audience-scoped surfaces, one search.',
      // Two audience-scoped surfaces, each in its own design register. The
      // Custos register is scoped to `operator/*` by the PageFrame override.
      components: {
        PageFrame: './src/components/PageFrame.astro',
      },
      // Forked token layer (Obsign + Brass Console), mapped onto Starlight's
      // variable scale. Self-hosted fonts, no runtime CDN.
      customCss: ['./src/styles/theme.css'],
      // Self-hosted repo link only; no third-party analytics or CDN scripts.
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/malpercio-dev/ezpds',
        },
      ],
      sidebar: [
        {
          label: 'Using Obsign',
          items: [
            { label: 'Welcome', slug: 'user' },
            { label: 'Getting started', slug: 'user/getting-started' },
            { label: 'Tamper monitoring & recovery', slug: 'user/recovery' },
            { label: '2-of-3 Shamir backup', slug: 'user/backup' },
            { label: 'Migrating your identity', slug: 'user/migration' },
          ],
        },
        {
          label: 'Running Custos',
          items: [
            { label: 'Overview', slug: 'operator' },
            { label: 'Running a relay', slug: 'operator/running-a-relay' },
            { label: 'Configuration', slug: 'operator/configuration' },
            { label: 'Backups & restore', slug: 'operator/backups' },
            { label: 'Moderation', slug: 'operator/moderation' },
            {
              label: 'Reference',
              items: [
                { label: 'HTTP & XRPC API', slug: 'operator/reference/api' },
                { label: 'Configuration', slug: 'operator/reference/config' },
                { label: 'Mobile IPC commands', slug: 'operator/reference/ipc' },
              ],
            },
          ],
        },
      ],
    }),
  ],
});
