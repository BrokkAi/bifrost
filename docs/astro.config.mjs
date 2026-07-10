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
      favicon: '/favicon.png',
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
            { label: 'CLI', slug: 'cli' },
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
            { label: 'Zed Agent', slug: 'zed-mcp' },
            { label: 'Amp', slug: 'amp' },
            { label: 'Antigravity', slug: 'antigravity' },
          ],
        },
        {
          label: 'Use Bifrost via LSP',
          items: [
            { label: 'LSP Server', slug: 'lsp' },
            { label: 'VS Code', slug: 'vscode' },
            { label: 'Zed', slug: 'zed-lsp' },
            { label: 'Neovim', slug: 'neovim' },
            { label: 'Helix', slug: 'helix' },
          ],
        },
        {
          label: 'Code Querying',
          items: [
            { label: 'Overview', slug: 'code-querying' },
            {
              label: 'Language Tutorials',
              items: [
                { label: 'Overview', slug: 'code-query-tutorials' },
                { label: 'Python', slug: 'code-query-tutorials/python' },
                { label: 'Java', slug: 'code-query-tutorials/java' },
              ],
            },
            { label: 'Semantic Search', slug: 'semantic-search' },
            { label: 'Rune Query Language', slug: 'rune-query-language' },
            { label: 'JSON CodeQuery', slug: 'code-query-json' },
          ],
        },
        {
          label: 'Use Bifrost as a Library',
          items: [
            { label: 'Rust Library', slug: 'rust-library' },
            { label: 'Python Client', slug: 'python-client' },
          ],
        },
      ],
    }),
  ],
});
