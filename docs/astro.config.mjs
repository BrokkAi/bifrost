import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = process.env.PUBLIC_DOCS_SITE ?? 'https://brokkai.github.io';
const productionBase = process.env.PUBLIC_DOCS_BASE ?? '/bifrost';
const isDev = process.argv.includes('dev');

export default defineConfig({
  site,
  base: isDev ? '/' : productionBase,
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
          label: 'Use Bifrost via MCP',
          items: [
            { label: 'MCP Server', slug: 'mcp' },
            { label: 'Agent Instructions', slug: 'agents' },
            { label: 'Codex', slug: 'codex' },
            { label: 'Claude Code', slug: 'claude-code' },
            { label: 'Cursor', slug: 'cursor' },
            { label: 'Amp', slug: 'amp' },
          ],
        },
        {
          label: 'Use Bifrost via LSP',
          items: [
            { label: 'LSP Server', slug: 'lsp' },
            { label: 'VS Code', slug: 'vscode' },
            { label: 'Neovim', slug: 'neovim' },
            { label: 'Helix', slug: 'helix' },
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
