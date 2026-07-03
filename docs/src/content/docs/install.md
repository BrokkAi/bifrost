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
