---
title: Cite Bifrost
description: Attribute the software and identify the exact analyzed version.
---

Bifrost publishes machine-readable citation metadata in
[`CITATION.cff`](https://github.com/BrokkAi/bifrost/blob/master/CITATION.cff).
GitHub uses this file for its **Cite this repository** action. Bifrost does not
currently publish a DOI, so cite it as versioned software and include the full
Git commit used for the analysis. A release number alone is insufficient when
the run used an unreleased checkout.

## Authorship And Project Lineage

The citation uses **Bifrost contributors** as a collective author. This is
intentional:

- Citation authorship records creative and scholarly credit; it is separate from
  copyright ownership. Brokk, Inc. remains the copyright owner and is listed as
  the project contact.
- Bifrost is a Rust port and continuation of analyzer architecture, resources,
  and tests developed in the Brokk Java codebase. The CFF metadata references
  [Brokk](https://github.com/BrokkAi/brokk) so that lineage is machine-readable
  instead of crediting only the people whose commits appear in the newer Rust
  repository.
- A Git commit count is not an authorship policy. It omits design, review,
  testing, documentation, and work ported across repositories, while treating
  every commit as the same kind of contribution.

The collective author avoids inventing an incomplete or arbitrary list of named
authors. If the project later adopts named authorship, define contribution
criteria first, ask people how they want their names and ORCIDs represented, and
review the ordered list for every release. The [Bifrost contributor
history](https://github.com/BrokkAi/bifrost/graphs/contributors) and [Brokk
contributor history](https://github.com/BrokkAi/brokk/graphs/contributors) remain
useful acknowledgements, but neither graph is a complete record of intellectual
contribution.

## Suggested Citation

Use this human-readable form and replace the placeholders:

> Bifrost contributors. *Bifrost: Tree-sitter-backed multi-language code analyzer*, version `<version>`, commit `<full-commit>`, `<year>`. https://github.com/BrokkAi/bifrost

A BibTeX software entry can use:

```bibtex
@software{bifrost_contributors_<year>,
  author  = {{Bifrost contributors}},
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
