import { unified } from '@astrojs/markdown-remark';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import rehypeBasePathLinks from './rehype-base-path-links.mjs';

const site = process.env.PUBLIC_DOCS_SITE ?? 'https://bifrost.brokk.ai';
const productionBase = process.env.PUBLIC_DOCS_BASE ?? '/';
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
      title: 'Bifrost',
      description: 'Documentation for Brokk Bifrost, the analyzer behind Brokk code intelligence.',
      head: [
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' } },
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: true } },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Rajdhani:wght@400;500;600;700&family=Staatliches&display=swap',
          },
        },
        { tag: 'meta', attrs: { property: 'og:image', content: socialCardUrl } },
        { tag: 'meta', attrs: { property: 'og:image:type', content: 'image/png' } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
        {
          tag: 'meta',
          attrs: {
            property: 'og:image:alt',
            content:
              'Bifrost code intelligence for AI, with structural queries and multi-language analysis designed for repository-scale use.',
          },
        },
        { tag: 'meta', attrs: { name: 'twitter:image', content: socialCardUrl } },
        {
          tag: 'meta',
          attrs: {
            name: 'twitter:image:alt',
            content:
              'Bifrost code intelligence for AI, with structural queries and multi-language analysis designed for repository-scale use.',
          },
        },
      ],
      customCss: ['./src/styles/brokk.css'],
      components: {
        Header: './src/components/BifrostHeader.astro',
        Hero: './src/components/BifrostHero.astro',
        ThemeProvider: './src/components/BifrostThemeProvider.astro',
        ThemeSelect: './src/components/EmptyThemeSelect.astro',
      },
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
            { label: 'Third-Party Notices', slug: 'third-party-notices' },
            { label: 'Overview', slug: 'overview' },
            { label: 'Capabilities', slug: 'capabilities' },
            { label: '10-Minute Evaluation', slug: 'evaluate-bifrost' },
            { label: 'Install Bifrost', slug: 'install' },
            { label: 'CLI', slug: 'cli' },
            { label: 'Scan a Codebase', slug: 'scan-a-codebase' },
            { label: 'Workspace Scope', slug: 'workspace-scope' },
          ],
        },
        {
          label: 'Use Bifrost via MCP',
          items: [
            { label: 'MCP Server', slug: 'mcp' },
            { label: 'Agent Instructions', slug: 'agents' },
            { label: 'Pi', slug: 'pi' },
            { label: 'Codex', slug: 'codex' },
            { label: 'Claude Code', slug: 'claude-code' },
            { label: 'Cursor', slug: 'cursor' },
            { label: 'OpenCode', slug: 'opencode' },
            { label: 'Zed Agent', slug: 'zed-mcp' },
            { label: 'Amp', slug: 'amp' },
            { label: 'Antigravity', slug: 'antigravity' },
            { label: 'DeepSeek Harness', slug: 'deepseek-harness' },
          ],
        },
        {
          label: 'Use Bifrost via LSP',
          items: [
            { label: 'LSP Server', slug: 'lsp' },
            { label: 'VS Code', slug: 'vscode' },
            { label: 'Cursor', slug: 'cursor' },
            { label: 'Zed', slug: 'zed-lsp' },
            { label: 'Neovim', slug: 'neovim' },
            { label: 'Helix', slug: 'helix' },
          ],
        },
        {
          label: 'Code Querying',
          items: [
            { label: 'Overview', slug: 'code-querying' },
            { label: 'Data Flow and Typestate', slug: 'data-flow-and-typestate' },
            { label: 'Build a Rule', slug: 'build-static-analysis-rule' },
            { label: 'Static-Analysis Policies', slug: 'static-analysis-policies' },
            { label: 'CI Gating with GitHub Actions', slug: 'ci-github-actions' },
            { label: 'Semantic-Model Packs', slug: 'semantic-model-packs' },
            { label: 'Agent Result Safety', slug: 'agent-result-safety' },
            { label: 'JSON CodeQuery', slug: 'code-query-json' },
            { label: 'Explain and Profile', slug: 'code-query-explain-profile' },
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
                    { label: 'Library Integration', slug: 'code-query-tutorials/library-integration' },
                    { label: 'Import Traversal', slug: 'code-query-tutorials/import-traversal' },
                    { label: 'Set Composition', slug: 'code-query-tutorials/set-composition' },
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
                    { label: 'Kotlin', slug: 'code-query-tutorials/kotlin' },
                  ],
                },
              ],
            },
          ],
        },
        {
          label: 'Design and Architecture',
          items: [
            { label: 'Overview', slug: 'design' },
            { label: 'System Architecture', slug: 'design/system-architecture' },
            { label: 'Identity and Language Front Ends', slug: 'design/identity-and-language-frontends' },
            { label: 'Storage and Cache Strategy', slug: 'design/storage-and-cache' },
            { label: 'Usage Analysis Engine', slug: 'design/usage-analysis' },
            { label: 'Dataflow Engine', slug: 'design/dataflow-engine' },
            { label: 'Semantic Models and Summaries', slug: 'design/semantic-models' },
            { label: 'Evidence and Result Contract', slug: 'design/evidence-and-results' },
            { label: 'Decisions and Outlook', slug: 'design/decisions-and-outlook' },
            { label: 'Related Work', slug: 'design/related-work' },
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
