# Scala task-ranked reference differential at `4589dd98`

## Selection and provenance

This is the authoritative Scala leg of the task-ranked campaign. Repository membership came from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["scala"])`, followed by a stable descending `task_count` sort. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The five repositories were passed to the runner explicitly:

| Repository | Eligible tasks | Pinned head | Baseline missing | Final missing |
| --- | ---: | --- | ---: | ---: |
| `scala-steward-org__scala-steward` | 147 | `362eee1daf169d1082d2f59a7d278141c3a3a6ec` | 9 | 10 |
| `zio__zio` | 106 | `a3098949fa1059903d70593430ac5052416514dc` | 3 | 14 |
| `linkerd__linkerd` | 72 | `ea82499d386e44e8958be58e0386f593e639645b` | 15 | 5 |
| `scalameta__metals` | 71 | `3cd80c90c41183245e8cb8f069083868c085142a` | 22 | 16 |
| `typelevel__fs2` | 62 | `c9efcdb67360b218208293b952ba9edcd2affe9c` | 6 | 2 |

`zio__zio-http` also had 62 tasks; the selector's stable order retained FS2. All five repositories are absent from `large-repos.csv`, and their tracked worktrees and final corpus records are clean.

The first clean task-ranked corpus was `/mnt/optane/tmp/reference-differential/scala-task-top5-b4e1fee2-final.jsonl`, SHA-256 `ff1dfaeab586cf1f103ea64a231c9ce680432002f9754d7386b8e14f0d88e12d`; its log SHA-256 is `3cffae4e3ce495125c3af1c6d1ff84be17be3cf4c7b8a745774639693fb703e7`. Its 55 raw missing rows were exhaustively reconciled as 12 Jonathan-owned defects, 13 rows owned by David, and 30 qualifier artifacts.

## Defects and fixes

Five solely `jbellis`-assigned issues were completed and closed:

- #661: seven inverse gaps spanning parser-owned parameter defaults, nearest-first exact lexical outer fields, and original terminals of renamed imports;
- #663: the previously repaired unqualified/inherited callable family, revalidated with no final residuals;
- #664: four wrong-forward sites caused by loss of physical lexical owner, declaration/package import precedence, and anonymous-refinement base identity;
- #1073: a valid Scala 2 identifier named `extension` was parsed as an unconditional Scala 3 keyword, truncating its implicit-class owner;
- #1086: same-FQN Scala 2/Scala 3 source-set replicas erased anonymous-refinement inverse references.

The main structured repairs are in `e6cdb12a`, `e0a52c9e`, and `7677ff72`. They preserve exact AST fields, lexical/import tiers, namespaces, physical `CodeUnit` identity, and fail-closed ambiguity barriers. No regex, source-text mini-parser, or text-search resolver fallback was added.

#1073 also exposed a persistence requirement. Parser-table semantics can change without changing the ABI/node/field vocabulary in the automatic analyzer fingerprint. Commit `49a04dbb` added the explicit Scala parser-revision epoch cutover and a regression proving an exact prior parsed blob becomes unavailable after generation advance. The subsequent upstream parser merge retained both #1016 and #1073 changes and uses the combined parser-revision salt.

The first attempted clean publication at `0d405bfd` was deliberately rejected after revealing the stale cache and #1086. Its two-record diagnostic artifact is `/mnt/optane/tmp/reference-differential/scala-task-top5-0d405bfd-stale-cache-invalid.jsonl`, SHA-256 `a104c9bf2406200271c070862cbfc46d9c8fddcf501decbd16e9d9c2b31f45e8`; its log SHA-256 is `16ed28acef5805a73635d55a67316f92436664892e6e16d510a1abd4874b564b`. It is not acceptance evidence.

## Residual disposition

The final corpus contains 47 raw `missing` classifications: Metals 16, ZIO 14, Linkerd 5, FS2 2, and Scala Steward 10. Sampling changed under the corrected parser, so every final row was classified from its own source bytes, AST-shaped focus, and exact forward targets rather than inherited by subtraction.

The complete ledger is `/mnt/optane/tmp/reference-differential/scala-task-top5-4589dd98-final-missing-ledger.tsv`, SHA-256 `52a16cbbe87f097384d115612d93b21a87a670a88ffbad687ab5da28d9c90831`. Independent review mechanically proved a bijection with all 47 JSONL keys, exact target equality, and 47/47 source-byte matches. Its dispositions are:

- 26 import-owner qualifiers;
- 8 nonterminal/nested-owner qualifiers;
- 9 Scala-to-Java inverse-boundary rows owned by David's #128;
- 4 concrete/default-trait parameterless rows owned by David's #419/#499;
- 0 Jonathan-actionable rows.

All 12 baseline #661/#664/#1073 keys are absent, the #1086 `Tracer.Type` witness is absent, and no final row belongs to #663's callable family. The David-assigned issues were not modified or closed.

## Acceptance evidence

The accepted source head is `4589dd989c66137293e96e35de9e58927c7bec4b`, pushed to `origin/master`. The rebuilt release runner SHA-256 is `560afc66f70a0680438c6c2506478d97f472e83598338ee0c11e987a19367580`.

The final five-repository artifact is `/mnt/optane/tmp/reference-differential/scala-task-top5-4589dd98-final.jsonl`, SHA-256 `b9e97b47f63585bb9299e5a6b221b216ffebf73649d0c4bf9c1b9105a6062bd9`; its log SHA-256 is `d8f443276f99cc5ed6d7471d3ed5cc3f044933c7eb8e14b9f84c3dec6924ba02`. All five records are completed at clean Bifrost and repository heads, share fingerprint `10e38a3cd001503bf529831b778b3b57a237feee181e27f53e19dce2fb620428`, and report zero file errors, candidate-limit events, skipped targets, or target truncation.

The run sampled 50,000 sites: 6,110 consistent, 306 editor-only, 43,537 inconclusive, 47 reviewed missing, and zero unproven. Aggregate repository runtime was 2,433.57 seconds.

Two clean persisted-cache witnesses prove the final roots directly:

- Metals #1073 `XtensionAbsolutePath.isWorksheet` at bytes `14033..14044`: `/mnt/optane/tmp/reference-differential/scala-metals-1073-4589dd98-persisted.jsonl`, SHA-256 `842281b9893f2f2787736b95e16c729ef8006bb34c2aef11c5d48f158be6b344`;
- ZIO #1086 physical Scala 2 `Tracer.Type` at bytes `427..431`: `/mnt/optane/tmp/reference-differential/scala-zio-1086-4589dd98-persisted.jsonl`, SHA-256 `59a22b8cd94050be0050fbc5ca291d2a75b7ba9b0ffa779221265674d991ec38`.

The complete `cargo test --features nlp,python` matrix passed before the final upstream integration. After integrating current `origin/master`, formatting and diff hygiene, the 148-test Scala inverse suite, 51-test Scala definition-precedence suite, focused parser and cache-epoch regressions, and all-target/all-feature Clippy with warnings denied passed. Independent post-merge review approved both fixes. Issues #661, #663, #664, #1073, and #1086 are closed with publication evidence.
