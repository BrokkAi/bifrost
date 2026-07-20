# PHP task-ranked reference differential at `64de341e`

## Selection and provenance

This is the authoritative PHP leg of the task-ranked campaign. Repository membership came from `tasks.task_repos(tasks.SFT_PREDICATES, langs=["php"])`, followed by a stable descending `task_count` sort. `SFT_PREDICATES` applies the required `large-repos.csv` exclusion. The five explicit runner inputs were:

| Repository | Eligible tasks | Pinned head | Baseline missing | Final missing |
| --- | ---: | --- | ---: | ---: |
| `laravel__framework` | 126 | `ebae97d18d3d56a3a6a31fb9f8c5150ec414bc61` | 33 | 0 |
| `cakephp__cakephp` | 95 | `ab608711674ac662af7315c5cdf1e0fbe2000e45` | 46 | 0 |
| `PHPOffice__PhpSpreadsheet` | 84 | `0577c74889e080c088e5af4585f3d71db9467804` | 188 | 0 |
| `grokability__snipe-it` | 82 | `660a5948d813a6a3e14518ae5600ee6a05e73b00` | 0 | 0 |
| `codeigniter4__CodeIgniter4` | 74 | `f9c71a7f8c34859008c426a507f40dbc883529f5` | 31 | 0 |

The baseline ran at clean Bifrost head `c0e01ba9` with JSONL SHA-256 `0e1fb71713e0fe0d9e6b4ab77da36730f58e15f0e801a5f3b288df8c41652ebd`. All 298 missing rows were exhaustively reviewed and were legitimate inverse false negatives.

## Defects and fixes

- #960 covered 96 owner-relative `self`, `static`, and `parent` references. The inverse graph now resolves these from the structured lexical owner and inheritance relation.
- #961 covered 200 call-return receiver-chain rows. A shared stack-safe structured receiver evaluator now follows declared field and callable return types and normalizes inherited members to their nearest unambiguous declaring owner.
- #962 covered four nullsafe calls. Ordinary and nullsafe member forms now use the same structured dispatch path. Two PhpSpreadsheet rows required both #961 and #962, so the issue counts intentionally overlap.

The implementation commit is `14aa44cb` and the accepted integrated head published to `origin/master` is `64de341e0d631f1b9c4138df63922374a63d16ba`. Issues #960, #961, and #962 were assigned only to `jbellis` before implementation and closed after production proof.

## Acceptance evidence

The clean detached release runner embedded the accepted source path and head. Its SHA-256 is `c2ab9b150125c6467ae5809511be4fdbc59381f60b1d6ed92786105703dbc7fc`.

The final five-repository artifact is `/mnt/optane/tmp/reference-differential/php-task-top5-64de341e-final.jsonl`, SHA-256 `12e80e0c30b982e54440c2ecf1e43b9e3bc05d632199067b6e57539337cd1e68`. All five records are clean and completed at `64de341e`, share fingerprint `258a23d1e1324bea56a9bc1c262f45e4cfe4d9612fafaee703f77dfff05a4820`, and report zero missing, inconclusive, diagnostics, and file errors. The log SHA-256 is `dc82b5ee13c5b838291cd9c2aa4fae1c8d1c7ee0d1bb95912783c4ccaabef254`.

Exact ephemeral post-fix witnesses also completed cleanly with zero actionable or inconclusive rows:

- owner-relative type: `php-exact-relative-type-64de341e.jsonl`, SHA-256 `7b9b5e04677b016b41326235551cd92e782ebc45b787a89b2d34ffb3604b788d`;
- call-return chain: `php-exact-chain-64de341e.jsonl`, SHA-256 `a8e60d2a79f7ed47153b4e1ebc4ff9e211b5a850fe377917139ca6357f81caa1`;
- nullsafe call: `php-exact-nullsafe-64de341e.jsonl`, SHA-256 `e35f654f550b90a8a533d25ddd50926bb76fcd2c965221513a05e7fa33f9bc48`.

Validation passed 51 targeted PHP graph tests, 18 whole-workspace PHP graph tests, `cargo fmt`, `git diff --check`, isolated all-target/all-feature Clippy, and the full `cargo test --features nlp,python` matrix. In the final integrated suite, all library tests passed and 186/187 LSP tests passed; the only suite-level failure was a child-process SIGKILL in the upstream shutdown-cleanup test under contention, and that exact test passed immediately in an unrestricted isolated rerun.
