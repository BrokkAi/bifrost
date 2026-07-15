---
title: Cite Bifrost
description: Attribute the software and identify the exact analyzed version.
---

Bifrost does not currently publish a DOI or `CITATION.cff`. Cite it as versioned software and include the full Git commit used for the analysis. A release number alone is insufficient when the run used an unreleased checkout.

## Suggested Citation

Use this human-readable form and replace the placeholders:

> BrokkAi. *Bifrost: Tree-sitter-backed multi-language code analyzer*, version `<version>`, commit `<full-commit>`, `<year>`. https://github.com/BrokkAi/bifrost

A BibTeX software entry can use:

```bibtex
@software{brokkai_bifrost_<year>,
  author  = {{BrokkAi}},
  title   = {Bifrost: Tree-sitter-backed Multi-language Code Analyzer},
  version = {<version>},
  year    = {<year>},
  url     = {https://github.com/BrokkAi/bifrost},
  note    = {Commit <full-commit>}
}
```

Get the identifiers from the exact binary and checkout used:

```bash
bifrost --version
git -C /path/to/bifrost rev-parse HEAD
```

If a packaged launcher supplied the binary, record the version printed by that binary and the plugin release or revision separately. Do not substitute the source checkout's commit when it was not the executable that ran.

## Cite The Analysis, Not Only The Engine

Software attribution does not make a result reproducible. Alongside the citation, publish the source repository revision, query and schema version, workspace scope, Bifrost configuration, proof policy, diagnostics, truncation state, and output artifact. Use the [analysis manifest](/reproduce-analysis/#run-manifest) as the minimum companion record.

When quoting a result, identify its evidence level. For example: “Bifrost 0.8.3 returned a proven indexed call edge at `path:line` for query revision `abc…`, with no execution diagnostics and `truncated: false`.” Avoid turning that bounded static result into an unqualified runtime or whole-program claim.
