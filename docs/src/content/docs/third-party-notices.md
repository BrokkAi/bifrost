---
title: Third-Party Notices
description: Third-party licensing and attribution for Bifrost artifacts.
---

Bifrost's public source is licensed under Apache-2.0. Official binaries,
packages, editor extensions, and semantic packs may also contain third-party
components or generated data under their own terms.

Each release artifact must include the notices generated for its exact locked
dependency graph. The checked-in `licenses/` and `semantic-packs/**/notices/`
files are the source inputs for those artifact-specific reports.

Bifrost-owned semantic packs are Apache-2.0. A pack built from third-party
material records that material's own license in the pack and identifies it in
the pack's notice file; `semantic-packs/jvm/temurin-jdk-21.0.8+9.json`, built
from OpenJDK under GPL-2.0-only with the Classpath exception, is the current
example.

No Bifrost source, artifact, or dependency is licensed under GPL-3.0 or
LGPL-3.0. Where a dependency does carry a reciprocal license -- libgit2 under
GPL-2.0 with a linking exception, its bundled winhttp definitions under
LGPL-2.1, and `option-ext` under MPL-2.0 on the optional `nlp` feature --
`licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt` reproduces the required text in
full alongside the binary.
