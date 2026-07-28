# Python task-ranked top-ten reference differential at `d3a3e9b6`

## Selection and provenance

This is the authoritative Python top-ten expansion. Repository membership came
from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["py"])`, followed by the
campaign's stable descending `task_count` ordering. `SFT_PREDICATES` applies
the required `large-repos.csv` exclusion. The ten repositories were passed to
the runner explicitly.

| Repository | Eligible tasks | Pinned head | Sampled | Queried targets | Missing |
| --- | ---: | --- | ---: | ---: | ---: |
| `bytedance__deer-flow` | 208 | `c9fb9768d476e28de0294ac7a23cab9819b93f83` | 10,000 | 913 | 0 |
| `pewdiepie-archdaemon__odysseus` | 137 | `a35384e68fb2b62e66500e800bf0779fceeba16b` | 10,000 | 580 | 0 |
| `kornia__kornia` | 112 | `9ec79b53249341b1baa2267911bbf58152539a14` | 10,000 | 590 | 4 |
| `quantumlib__Cirq` | 105 | `6922063c70b2ef6d1a13bc39a0921185cebfffeb` | 10,000 | 950 | 301 |
| `powsybl__powsybl-core` | 97 | `5a3e7cc8b6486285c4c3225c253351ea467973f0` | 105 | 8 | 0 |
| `mahmoud__glom` | 90 | `6fd41340f30519ddc64a546ad2703dfe53f12356` | 7,149 | 296 | 0 |
| `caikit__caikit` | 84 | `9396e76bedd53ddd8dcd14701285a10858ddf1d5` | 10,000 | 790 | 0 |
| `keras-team__keras` | 70 | `9d36a67f0ead90836f61631580bb9a2ae1f2f532` | 10,000 | 696 | 64 |
| `fsspec__filesystem_spec` | 65 | `82d24f76f39fbc45a6a18af5d98d88a785bc43f9` | 10,000 | 537 | 0 |
| `python-websockets__websockets` | 57 | `ff4869ba468129f3e85b08c2a8a03ec45cf26537` | 10,000 | 647 | 8 |

The accepted source head is
`d3a3e9b69c4ade1d4c13409cc7378d8efe298191`, equal to
`origin/master` before the run. Its clean release runner SHA-256 is
`27c52e96c53f78b8a4419a26552baa39a6ad08a065c224387a096384d6b293c1`.
All ten records completed with false Bifrost and repository dirty flags and
share run fingerprint
`292be91e9bf4dec85d7726e7814046bcee21b7a2451a0c2d70ea2f102538a572`.

The strict run used three concurrent repository jobs, eight inner workers per
repository, persisted caches, and the standard bounds: 1,000 files, 10,000
sampled sites, 50,000 candidates per file, 4 MiB per source, 1,000 targets,
1,000 usage files, 100,000 usages, and seed zero. Parallel repository
scheduling changes only envelope completion order. No record reports a file
error, candidate-limit event, skipped target, or target-truncated site.

## Defect closure and residual audit

The previous clean top-ten report at `c6dacc42` contained 379 raw missing
rows. Exhaustive review classified 377 as non-actionable forward-premise
artifacts in the Cirq, Keras, websockets, and Kornia module/import collision
families. The two legitimate rows were Caikit annotation references:
`ModelFutureBase` and `method.signature.return_type`.

Issue #1225 was created with the required `FIRD:` prefix and assigned to
`jbellis` before implementation. The structural fix preserves exact class
ownership for decorated method annotations and merges declaration-time outer
typed-binding facts into nested closure annotations while respecting function
and lambda shadowing. Seven focused behavior tests, the complete 113-test
Python graph suite, the five workspace-graph tests, formatting, all-target
all-feature Clippy, and the complete `nlp,python` test matrix passed at
niceness 10 with normal Cargo storage. Commit `ced3b59f` was pushed to
`origin/master`, exact Caikit replays became consistent, and #1225 was closed.

An exact identity comparison of
`(repository, path, byte range, text, forward targets)` between the old and
final reports proves:

- 379 old missing rows;
- 377 final missing rows;
- exactly the two fixed Caikit identities removed;
- zero novel identities.

The 377 retained raw rows are therefore the already dispositioned
non-actionable partition, not unresolved symbols defects. The final aggregate
over 87,254 sampled sites is 7,445 consistent, 3,835 editor-only, 15
conservatively unproven, 75,582 inconclusive, and 377 raw missing.

## Accepted artifacts

The final report is
`/mnt/optane/tmp/bifrost-fird/python-task-top10-d3a3e9b6-cert.jsonl`,
SHA-256
`4f8689d10ab24f4e81d004f29ba8632eb9764a2aff661ac358017e41e6538911`.
Its log is
`/mnt/optane/tmp/bifrost-fird/python-task-top10-d3a3e9b6-cert.log`,
SHA-256
`5ac5b8dfe6a532b84b5e0ef4bb7b9ddce4c69330bd48611992e40dd9c5832581`.
The strict runner's expected exit status was 2 because auditable raw missing
rows remain. It completed all ten envelopes in 6 minutes 49 seconds. Python
finishes with zero actionable residuals.
