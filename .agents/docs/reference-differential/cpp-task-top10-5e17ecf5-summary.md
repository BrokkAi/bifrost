# C++ task-ranked top-ten reference differential at 5e17ecf5

## Selection and provenance

Selection used the live
`tasks.task_repos(tasks.SFT_PREDICATES, langs=["cpp"])` result, including the
selector's `large-repos.csv` exclusion, followed by stable
`(-task_count, repo_slug)` ordering. The runner received the ten repository
slugs explicitly, so finish-order JSONL append behavior could not change
membership. The accepted run used clean Bifrost head
`5e17ecf53c3ffc620452b0bee0ab022c6ecd0ac4`; every repository was also clean at
its pinned head.

| Rank | Repository | Tasks | Pinned head | Audited files | Sampled | Queried / distinct targets | Raw missing | Seconds |
| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | `esphome__esphome` | 151 | `9327d011fc95dbb710e46917218cce09b86f2cbe` | 1,000 | 10,000 | 1,000 / 2,070 | 0 | 80.2 |
| 2 | `cloudflare__circl` | 68 | `901199c7d4fcefc8c43e8ad46397439ccd3a0ed0` | 7 | 1,035 | 21 / 21 | 0 | 0.5 |
| 3 | `ljharb__qs` | 32 | `9198d2bc3d5c90c2e12f514204ca2121ddb4ad7b` | 0 | 0 | 0 / 0 | 0 | 0.0 |
| 4 | `PJK__libcbor` | 32 | `9b78da40511f86df53e8541b646bad042dd785da` | 26 | 1,234 | 59 / 59 | 0 | 0.4 |
| 5 | `apache__qpid-proton` | 27 | `976e2181c4c1daa6b84fd81465a0ca5cb98b39b8` | 271 | 10,000 | 1,000 / 1,169 | 14 | 80.8 |
| 6 | `LMCache__LMCache` | 25 | `495cc9a8ce72be0d188448a456b373e4984f548b` | 52 | 10,000 | 315 / 315 | 0 | 4.6 |
| 7 | `zeromq__libzmq` | 22 | `ba63f0372701751f5435dbfbdaf23ab3dc1ae320` | 310 | 10,000 | 971 / 971 | 3 | 34.2 |
| 8 | `apache__logging-log4cxx` | 22 | `a345ec7de5971990f13c0943b4505a928df4c8b1` | 419 | 10,000 | 495 / 495 | 36 | 62.6 |
| 9 | `Blosc__c-blosc2` | 21 | `e96d12312d5a80aab12df0155ff8175aefacbf18` | 44 | 9,908 | 153 / 153 | 0 | 22.0 |
| 10 | `ccache__ccache` | 20 | `ddd9437c23337aba77216d9bafe06e495478ac6f` | 180 | 10,000 | 971 / 971 | 5 | 277.6 |

`ljharb__qs` is the selector-faithful zero-file envelope: its pinned clone has
no eligible C++ translation unit. ESPHome and Qpid alone reached the deliberate
1,000-target bound. Their 1,239 skipped targets and 1,944 affected sites are
accounted as inconclusive, never missing.

The release runner SHA-256 is
`ee5f26d6103e2daec0083b706f3acbf71a0be4a5bdd95ca97df10756fb1b4855`.
All ten records share run fingerprint
`93d14bd1be30a52546ab0ffc7063678e11b5ef14fa367215488ef93749c15367`.
The run used four repository jobs, twelve inner workers, persisted cache,
`max_files=1000`, `max_sites=10000`, `max_candidates_per_file=50000`,
`max_source_bytes=4194304`, `max_targets=1000`, `max_usage_files=1000`,
`max_usages=100000`, and seed zero. It completed in 5:13.45 at niceness 10
with normal Cargo storage. All ten envelopes completed; there were zero file
errors and zero candidate-limit events.

The aggregate contains 72,177 sampled sites across 2,309 audited files:
10,422 consistent, 367 editor-only, 1,034 unproven, 60,296 inconclusive, and
58 raw missing. It queried 4,985 of 6,224 distinct targets.

## Defect closure and residual audit

The clean pre-final report at `d3a3e9b6` contained 81 raw missing identities.
Exact `(repository, path, byte range, sorted target identity)` comparison
against the final report removed 23 identities and introduced none. The
removed set contains every filed final witness:

- #1185 restores the two explicit Qpid receiver calls and the bare
  `value::clear` self call. Concrete receiver ownership is preserved across
  inherited-member recovery, and out-of-line operator bodies recover their
  structured owner.
- #1186 rejects the four CIRCL assembly-macro tail tokens as recovered
  non-reference source. Production parity required accepting erroneous
  tree-sitter wrapper siblings through `has_error()`; explicit descendant
  `ERROR` containment was too narrow for the `R12` parse.
- #1226 prevents a qualified type owner range from being rebound to the
  same-named Qpid method.

The same root-cause fixes removed 15 additional previously reviewed
declaration/type-owner artifacts. Issues #1185, #1186, and #1226 were assigned
to `jbellis` before their final changes, fixed on the existing branch, pushed
directly to `origin/master`, and closed. Their final correcting commits are
`e1acf863`, `5e17ecf5`, and `4edf61e3`, respectively.

All 58 remaining identities are an exact subset of the exhaustively reviewed
`d3a3e9b6` set. Fifty-six are declaration, out-of-line self-owner, or
mis-forwarded type-head sites for which inverse omission is correct. The other
two are Qpid `proton::get` link-unit cases whose available project structure
supports only an exact unproven result. No remaining identity is actionable.
The strict runner therefore returned status 2 for raw disagreement, not for an
infrastructure or unowned product failure.

Clean-head exact artifacts for the final filed witnesses are:

- CIRCL `R15`:
  `circl-r15-5e17ecf5-final-exact.jsonl`,
  SHA-256 `f008dafb9d75fedda40c18645f7c58f0778fc1130c267547768afca5f33cb1c9`;
- CIRCL `MULXQ`:
  `circl-mulxq-5e17ecf5-final-exact.jsonl`,
  SHA-256 `77c5949b4867eb6d38dfece87a2f940074101051004491eb072b70d628c826ee`;
- CIRCL `DX`:
  `circl-dx-5e17ecf5-final-exact.jsonl`,
  SHA-256 `1448176f9818dbc1a0f74a2ddab7cacec52145ef3f04849e6545905d69de45b2`;
- CIRCL `R12`:
  `circl-r12-5e17ecf5-final-exact.jsonl`,
  SHA-256 `274f43f57aa8c3a69043e92fb070bb6f828db82827da2e6c67fd04f8f998efa7`;
- Qpid `session::error`:
  `qpid-error-5e17ecf5-final-exact.jsonl`,
  SHA-256 `180d20805b9d4594e765ec855a77850f1762d5c7d5fb22bcacb99e25a6c28849`;
- Qpid `session::uninitialized`:
  `qpid-uninitialized-5e17ecf5-final-exact.jsonl`,
  SHA-256 `f7e738ad71b03b138e1e536dc8783a8240bd445e2be4be6b50d793394eead579`;
- Qpid `value::clear`:
  `qpid-clear-5e17ecf5-final-exact.jsonl`,
  SHA-256 `9317f8c906eb52ae2db4d1decbd380739766c680bf613f048953b9489bf2772d`.

The first four return structured `no_definition` with
`declaration_or_import_site`; the two explicit receiver calls are consistent;
and `value::clear` is an exact editor-only `self_receiver` hit. The #1226
Qpid replay is
`qpid-node-options-distribution-mode-4edf61e3-exact.jsonl`; it is consistent
with zero missing and has SHA-256
`3bd50ac14c4e7d74282f98bcfae4042e6822565aebf000e1b96a7623bab5dc09`.

## Accepted artifacts

The accepted raw report is
`/mnt/optane/tmp/bifrost-fird/cpp-task-top10-5e17ecf5-final.jsonl`, SHA-256
`9397f5381ee975b7a894cdd44c7bccd76c598524d1260fab32a5a26dadfa8e70`.
Its log SHA-256 is
`05e23c9dd00b2e919e17ff953864cb1eee8239de7c18987755ea362d60f29e36`.
These temporary files may be removed after this checked-in compact evidence is
published and the campaign-level audit is complete.
