# Python task-ranked reference differential at `acd388c4`

## Selection and provenance

This is the authoritative Python leg of the task-ranked campaign. Repository membership came from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["py"])`, followed by a stable descending `task_count` sort. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The five repositories were passed to the runner explicitly:

| Repository | Eligible tasks | Pinned head | Queried targets | Missing |
| --- | ---: | --- | ---: | ---: |
| `bytedance__deer-flow` | 208 | `c9fb9768d476e28de0294ac7a23cab9819b93f83` | 913 | 0 |
| `pewdiepie-archdaemon__odysseus` | 137 | `a35384e68fb2b62e66500e800bf0779fceeba16b` | 580 | 0 |
| `kornia__kornia` | 112 | `9ec79b53249341b1baa2267911bbf58152539a14` | 590 | 0 |
| `quantumlib__Cirq` | 105 | `6922063c70b2ef6d1a13bc39a0921185cebfffeb` | 950 | 0 |
| `powsybl__powsybl-core` | 97 | `5a3e7cc8b6486285c4c3225c253351ea467973f0` | 8 | 0 |

Powsybl-core is intentionally retained: the live selector classifies it as Python and admits it after all task filters, even though this checkout exposes only `docs/conf.py` to the Python analyzer.

The accepted source head is `acd388c4acfd69d2ff8879e40a099228da8e4ef1`, pushed directly to `origin/master` before the run and verified equal to the remote-tracking head. Its clean release runner SHA-256 is `a0a2ff675ec92b51361367fc39f1ed46e7d8c851f56607c00db35afa67036752`. All Bifrost and repository dirty flags are false, all five records have status `completed`, and every record shares semantic fingerprint `292be91e9bf4dec85d7726e7814046bcee21b7a2451a0c2d70ea2f102538a572`.

The campaign used the standard strict bounds: one repository job, eight inner workers, persisted cache mode, 1,000 files, 10,000 sampled sites, 50,000 candidates per file, 4 MiB per source, 1,000 queried targets, 1,000 usage files, 100,000 usages, and seed zero. No record reports a file error, candidate-limit event, skipped target, or target-truncated site.

## Defects and repairs

The pinned baseline at source head `0b4f1d6f` contained seven legitimate missing rows: four in Cirq and three in Kornia. They reduced to four structured roots:

- #795: inverse usage omitted module qualifiers and re-export aliases;
- #1096: inverse usage omitted members selected from attribute-callee return types;
- #1097: grouped Python imports were reconstructed by forbidden source-text splitting instead of tree-sitter bindings;
- #1098: dotted module aliases collapsed forward identity to the parent package.

All four issues were assigned solely to `jbellis` before implementation. The fixes introduced one AST-derived import binding representation, invalidated stale Python analyzer cache rows, preserved exact dotted-module identity, used structured callable return metadata, and resolved inverse namespace paths through exact namespace binders and the canonical export resolver.

The first clean post-publication replay removed all seven rows but exposed fourteen further #795 witnesses: five in Cirq and nine in Kornia. Thirteen used arbitrary-depth namespace paths such as `K.feature.DISK`, `kornia.core.ops.eye_like`, and `cirq.testing.random_special_unitary`. The last was a direct child-module decorator qualifier, `@value.value_equality`. Deep namespace resolution now walks tree-sitter attribute fields from the exact import root and compares the canonical resolved `CodeUnit`. That final Cirq row also exposed module scope facts incorrectly absorbing a nested method parameter named `value`; module and function fact collection now stop at nested function, class, and lambda boundaries, while the separate class-field inference pass keeps its intended behavior.

Behavior coverage includes the 103-test targeted Python inverse suite and 17-test whole-workspace graph suite, with exact namespace re-export, direct-module, class-decorator, shadowing, and lexical-boundary controls. Formatting, `cargo fmt --all -- --check`, isolated `cargo clippy --all-targets --all-features -- -D warnings`, and the complete `cargo test --features nlp,python` matrix passed after each required `origin/master` integration. The final integration included two concurrent upstream merges and was fully revalidated before publication.

## Exact and corpus results

All twenty-one formerly missing production sites were replayed individually with ephemeral caches against the clean pushed runner. The artifact is `/mnt/optane/tmp/bifrost-fird/python-former-missing-exact-acd388c4.jsonl`, SHA-256 `2988e77b2b5b3e3aefd1184e93a6e5ba8ffe706b7a74d47aa01ff88cb38176f6`; its log SHA-256 is `23bdb03f65bb6dd21a08741a210431e77ec2ae8258e0cc6dc1fe62116a12178a`. All 21 records completed, all used head `acd388c4`, and they contain zero missing rows, dirty flags, or file errors.

The final artifact is `/mnt/optane/tmp/bifrost-fird/python-task-top5-acd388c4-clean.jsonl`, SHA-256 `416ed1a025d9967e3fe1731a18f3c188935029de62877a10f9d84622cff99e99`. Its log is `/mnt/optane/tmp/bifrost-fird/python-task-top5-acd388c4-clean.log`, SHA-256 `69f7ddd1f1384fa59b2c53bdbefdcafcad88a25488ebdebc0b90070a1724e648`.

Across 40,105 sampled sites, the final runner classified 4,814 consistent, 5 conservatively unproven, 35,286 inconclusive, and zero missing:

| Repository | Sampled sites | Consistent | Unproven | Inconclusive | Missing |
| --- | ---: | ---: | ---: | ---: | ---: |
| `bytedance__deer-flow` | 10,000 | 1,148 | 0 | 8,852 | 0 |
| `pewdiepie-archdaemon__odysseus` | 10,000 | 834 | 3 | 9,163 | 0 |
| `kornia__kornia` | 10,000 | 774 | 0 | 9,226 | 0 |
| `quantumlib__Cirq` | 10,000 | 2,047 | 2 | 7,951 | 0 |
| `powsybl__powsybl-core` | 105 | 11 | 0 | 94 | 0 |

Issues #795, #1096, #1097, and #1098 were closed only after this clean exact and corpus evidence was posted. Python therefore finishes with zero actionable residuals.
