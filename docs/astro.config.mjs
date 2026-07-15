import { unified } from '@astrojs/markdown-remark';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import rehypeBasePathLinks from './rehype-base-path-links.mjs';

const site = process.env.PUBLIC_DOCS_SITE ?? 'https://brokkai.github.io';
const productionBase = process.env.PUBLIC_DOCS_BASE ?? '/bifrost';
const isDev = process.argv.includes('dev');
const socialCardPath = [
  productionBase.replace(/^\/+|\/+$/g, ''),
  'bifrost-social-card.png',
]
  .filter(Boolean)
  .join('/');
const socialCardUrl = new URL(`/${socialCardPath}`, site).href;

export default defineConfig({
  site,
  base: isDev ? '/' : productionBase,
  markdown: {
    processor: unified({
      rehypePlugins: [[rehypeBasePathLinks, { base: isDev ? '/' : productionBase }]],
    }),
  },
  integrations: [
    starlight({
      title: 'Bifrost Docs',
      description: 'Documentation for Brokk Bifrost, the analyzer behind Brokk code intelligence.',
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: socialCardUrl } },
        { tag: 'meta', attrs: { property: 'og:image:type', content: 'image/png' } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        {
          tag: 'meta',
          attrs: {
            property: 'og:image:alt',
            content: 'Bifrost static analysis for agents, editors, and large repositories.',
          },
        },
        { tag: 'meta', attrs: { name: 'twitter:image', content: socialCardUrl } },
        {
          tag: 'meta',
          attrs: {
            name: 'twitter:image:alt',
            content: 'Bifrost static analysis for agents, editors, and large repositories.',
          },
        },
      ],
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
            { label: 'Choose Bifrost', slug: 'choose-bifrost' },
            { label: 'License and Use Cases', slug: 'license-use-cases' },
            { label: 'Overview', slug: 'overview' },
            { label: 'Capabilities', slug: 'capabilities' },
            { label: '10-Minute Evaluation', slug: 'evaluate-bifrost' },
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
            { label: 'Build a Rule', slug: 'build-static-analysis-rule' },
            { label: 'Agent Result Safety', slug: 'agent-result-safety' },
            { label: 'Semantic Search', slug: 'semantic-search' },
            { label: 'JSON CodeQuery', slug: 'code-query-json' },
            {
              label: 'Rune Query Language',
              items: [
                { label: 'Overview', slug: 'rune-query-language' },
                { label: 'Rune IR', slug: 'rune-ir' },
                { label: 'VS Code', slug: 'rql-vscode' },
                {
                  label: 'Language Tutorials',
                  items: [
                    { label: 'Overview', slug: 'code-query-tutorials' },
                    { label: 'Import Traversal', slug: 'code-query-tutorials/import-traversal' },
                    { label: 'Reference Traversal', slug: 'code-query-tutorials/reference-traversal' },
                    { label: 'Receiver Traversal', slug: 'code-query-tutorials/receiver-traversal' },
                    { label: 'Python', slug: 'code-query-tutorials/python' },
                    { label: 'Java', slug: 'code-query-tutorials/java' },
                    { label: 'JavaScript', slug: 'code-query-tutorials/javascript' },
                    { label: 'TypeScript', slug: 'code-query-tutorials/typescript' },
                    { label: 'Go', slug: 'code-query-tutorials/go' },
                    { label: 'C and C++', slug: 'code-query-tutorials/cpp' },
                    { label: 'Rust', slug: 'code-query-tutorials/rust' },
                    { label: 'PHP', slug: 'code-query-tutorials/php' },
                    { label: 'Scala', slug: 'code-query-tutorials/scala' },
                    { label: 'C#', slug: 'code-query-tutorials/csharp' },
                    { label: 'Ruby', slug: 'code-query-tutorials/ruby' },
                  ],
                },
              ],
            },
          ],
        },
        {
          label: 'Evaluate and Trust',
          items: [
            { label: 'Evidence and Methodology', slug: 'evaluation-evidence' },
            { label: 'Data Boundaries', slug: 'data-boundaries' },
            { label: 'Cite Bifrost', slug: 'cite-bifrost' },
            { label: 'Reproduce an Analysis', slug: 'reproduce-analysis' },
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
