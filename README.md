# Why bifrost

`bifrost` is Brokk's Rust-based static analysis toolbox for AI coding harnesses,
editors, and large repositories.

In a nutshell:

1. Bifrost parses unbuilt or partially broken repositories, including mixed-language workspaces.
1. Bifrost is designed for concurrency, with snapshot isolation and fast incremental updates when code changes underneath.
1. Bifrost is fast and lazy; it avoids optional work such as import analysis unless a request needs it.
1. Bifrost can be used through MCP, LSP, the command line, Python, or Rust.

## Documentation

The public documentation site lives in [`docs/`](docs/) and is published at
[brokkai.github.io/bifrost](https://brokkai.github.io/bifrost/).

Useful starting points:

- [Overview](docs/src/content/docs/overview.md)
- [Install Bifrost](docs/src/content/docs/install.md)
- [MCP server and toolsets](docs/src/content/docs/mcp.md)
- [LSP server](docs/src/content/docs/lsp.md)
- [CLI usage](docs/src/content/docs/cli.md)
- [Rust library usage](docs/src/content/docs/rust-library.md)
- [Python client usage](docs/src/content/docs/python-client.md)
- [Semantic search](docs/src/content/docs/semantic-search.md)

Run the docs site locally with:

```bash
cd docs
npm install
npm run dev
```

GitHub Pages publication is handled by `.github/workflows/docs.yml`. Release tag
builds publish both the latest docs site and a versioned snapshot under
`versions/<tag>/`.

## Language Coverage

Bifrost includes analyzers for Java, JavaScript, TypeScript, Rust, Go, Python,
C, C++, C#, PHP, Scala, and Ruby.

## Contributing

For local development, test commands, repository-local Python workflow, and
release tagging, see [CONTRIBUTING.md](CONTRIBUTING.md).
