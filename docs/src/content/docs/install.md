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

See [Semantic Search](../semantic-search/) for model, accelerator, and index details.
