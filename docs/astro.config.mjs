import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = process.env.PUBLIC_DOCS_SITE ?? 'https://brokkai.github.io';
const base = process.env.PUBLIC_DOCS_BASE ?? '/bifrost';

export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: 'Bifrost Docs',
      description: 'Documentation for Brokk Bifrost, the analyzer behind Brokk code intelligence.',
      customCss: ['./src/styles/brokk.css'],
      favicon: '/favicon.svg',
      editLink: {
        baseUrl: 'https://github.com/BrokkAi/bifrost/edit/master/docs/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/BrokkAi/bifrost',
        },
      ],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', slug: 'overview' },
            { label: 'Install Bifrost', slug: 'install' },
          ],
        },
        {
          label: 'Use Bifrost',
          items: [
            { label: 'MCP Server', slug: 'mcp' },
            { label: 'VS Code LSP', slug: 'vscode' },
          ],
        },
        {
          label: 'Release Docs',
          items: [{ label: 'Versioned Docs', slug: 'releases/versioned-docs' }],
        },
      ],
    }),
  ],
});
