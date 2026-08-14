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

Semantic packs that were already public at the open-core cutoff retain the
license recorded in each pack. The corresponding retained GNU license texts
are provided as `licenses/LGPL-3.0.md` and `licenses/GPL-3.0.md`. New
Bifrost-owned open-core packs use Apache-2.0 unless their own provenance states
otherwise.
