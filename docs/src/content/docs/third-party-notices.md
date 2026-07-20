---
title: Third-Party Notices
description: Dependency-license scope and notice locations for Bifrost binaries, wheels, editor extensions, plugins, and optional NLP components.
---

Bifrost incorporates open-source dependencies with their own licenses. Those
licenses do not change Bifrost's `LGPL-3.0-or-later` license, but distributors
must preserve the notices and license texts required by each dependency.

This page explains where the authoritative, generated notices live. It is a
practical orientation, not legal advice. The license text shipped with each
component controls.

## Notices By Artifact

| Artifact                     | Code incorporated into the artifact                                                         | Notice material shipped with it                                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| GitHub release archive       | Bifrost, the locked Rust graph, and target-dependent vendored native libraries              | `LICENSE.md`, `GPL-3.0.md`, `SOURCE.md`, `THIRD_PARTY_LICENSES.html`, and `SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` beside the binary |
| Python wheel                 | Bifrost, the locked Rust graph, the `python` feature, and vendored native libraries         | The same five files under the wheel's `.dist-info/licenses` tree                                                                   |
| VS Code extension            | The Bifrost extension and production npm packages bundled into `out/extension.js`           | `LICENSE.md`, `GPL-3.0.md`, `SOURCE.md`, and a VSIX-specific `THIRD_PARTY_LICENSES.txt`                                            |
| Agent plugin archive         | Bifrost launcher and agent instructions; no third-party npm runtime packages                | `LICENSE.md`, `GPL-3.0.md`, and `SOURCE.md` in the plugin root                                                                     |
| Rust crate or source archive | Bifrost source plus Cargo metadata; dependencies are obtained as separately licensed crates | Bifrost's `LICENSE.md` and `licenses/GPL-3.0.md`; dependency packages carry their own source notices                               |

The VS Code extension and agent plugin download the platform-specific Bifrost
release archive instead of embedding its executable. The downloaded archive
therefore carries its own Rust dependency report in addition to the notice files
inside the extension or plugin.

The Rust dependency report shipped in each binary archive and Python package is
generated during release from the tagged `Cargo.lock`, the default plus
`python` feature graph, and the union of targets used by the binary and wheel
release workflows. A single generated report is shared by every packaging job
in a workflow run; it is not a hand-maintained or source-controlled package
list.

Cargo metadata describes the Rust wrapper crates, but does not expose separate
`NOTICE` files or every license inside native source trees compiled by `*-sys`
crates. The companion
[`SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt`](https://github.com/BrokkAi/bifrost/blob/master/licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt)
therefore reproduces Moka's standalone notice and the notices for bundled
libgit2 and its components, zlib, SQLite, and tree-sitter's Unicode data. It also
links to the exact source crates resolved by `Cargo.lock`. The VSIX report is
generated from the production entries in `editors/vscode/package-lock.json`
after a locked `npm ci` install.

## Corresponding Source

Every official artifact reports a version `X.Y.Z`. Its complete corresponding
source is Git tag `vX.Y.Z` in the [Bifrost release
history](https://github.com/BrokkAi/bifrost/releases). The `SOURCE.md` included
with the artifact records this mapping and points recipients to the matching
source archive and build scripts.

This version-to-tag mapping matters: a link to `master` or to a newer release is
not a substitute for the source that produced a particular binary.

## Optional Semantic Search Components

Official command-line release archives currently use default features, and
official Python wheels enable `python`; neither artifact enables the optional
Rust `nlp` feature.

An organization that distributes its own NLP-enabled Bifrost binary must
regenerate the Rust notice report for that feature set. The `nlp` graph includes
`option-ext` under `MPL-2.0` through `hf-hub`. MPL 2.0 permits the executable to
be distributed as part of the larger Bifrost work, but recipients must be told
how to obtain the MPL-covered source. See the [MPL 2.0 executable-distribution
requirements](https://www.mozilla.org/en-US/MPL/2.0/#distribution-of-executable-form).

At runtime, semantic search separately downloads
[`voyageai/voyage-4-nano`](https://huggingface.co/voyageai/voyage-4-nano), whose
official model repository declares `Apache-2.0`, and uses Python packages such
as PyTorch, Transformers, and NumPy installed by `uv`. Those downloads are not
embedded in today's Bifrost release archives or wheels. If you redistribute or
bundle them, review and ship their own license and notice material too. Apache
2.0 redistribution requires a copy of the license and preservation of any
applicable `NOTICE` attribution; see the [Apache License
2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Build Tooling And Documentation

Development and documentation build dependencies are locked for reproducibility,
but a build tool is not automatically incorporated into the artifact it
produces. For example, platform-specific Sharp/libvips and Lightning CSS packages
used while building the documentation site are not placed in Bifrost's binary,
wheel, VSIX, or plugin archives.

Do not copy this distinction blindly into another packaging system. A container,
single-file bundler, vendored toolchain, or on-premise image can contain files
that the official workflows leave outside their artifacts. Inspect the actual
delivered bytes and regenerate notices for that distribution.

## Maintaining The Reports

Dependency updates must pass the repository's deny-by-default Cargo license
policy. CI verifies that the Rust report can be generated, and release workflows
generate and package it from the tagged lockfile. Supplemental and VSIX reports
are also generated from their lockfiles so an unreviewed license or missing
notice cannot silently enter an artifact.

For Bifrost's own copyleft and integration obligations, return to [License and
Use Cases](/license-use-cases/). The GNU LGPLv3 text is in
[`LICENSE.md`](https://github.com/BrokkAi/bifrost/blob/master/LICENSE.md), and
the incorporated GNU GPLv3 text is in
[`licenses/GPL-3.0.md`](https://github.com/BrokkAi/bifrost/blob/master/licenses/GPL-3.0.md).
