---
title: Install Bifrost
description: Install the released Bifrost binary or build it from source.
---

Install the released binary with Cargo:

```bash
cargo install brokk-bifrost --locked --force
```

For local development, build this checkout:

```bash
cargo build --bin bifrost
```

Check that the binary is available:

```bash
bifrost --help
```

When configuring tools that spawn Bifrost, prefer an absolute binary path unless `bifrost` is intentionally installed on the host `PATH`.

The packaged agent plugin uses a separate launcher that can download its pinned, checksum-verified Bifrost release into a user cache. See [Data and Trust Boundaries](/data-boundaries/#plugin-launcher-downloads-and-cache) for resolution order, cache locations, and the controls that disable or relocate downloads.

## Python Package

Install the native Python client with pip:

```bash
pip install brokk-bifrost-searchtools
```

Import it as `bifrost_searchtools`. See [Python Client](../python-client/) for the API surface and local development workflow.

## Optional Semantic Search

Semantic search is not part of the default Rust feature set. Build with `--features nlp` and enable it at runtime:

```bash
cargo build --features nlp --bin bifrost
BIFROST_SEMANTIC_INDEX=auto bifrost --root /path/to/project --mcp core
```

This `core` example is intentionally scoped to symbol navigation plus optional semantic search; it does not expose `query_code`. Use `--mcp "symbol|extended"` for a structural-query-capable agent, or add `extended` to the composition when semantic search and structural queries are both required.

See [Semantic Search](../semantic-search/) for model, accelerator, and index details.
