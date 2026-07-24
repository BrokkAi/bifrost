# Bounded data-flow artifact lifecycle benchmark — 2026-07-24

This report records the issue #817 lifecycle decision for the current bounded exploded data-flow state. It measures request-local ICFG construction and two solver clients; it does not construct a serialized candidate because concrete seeds, run-local fact IDs, worklists, truncations, and reached results are not reusable procedure summaries.

## Decision

**Recommendation: `ephemeral_not_eligible; persist reusable summaries only after #823 defines and measures them`.**

All 56 retained v2 samples reproduced identical dataset provenance, canonical SHA-256 ICFG topology and semantic work, client fact/reached counts, five solver-work counters, termination, completeness, shallow retained bytes, and result checksums. The topology checksum sorts stable procedure-local node identities, typed edges, and typed boundaries and excludes snapshot-local pointers, dense numbering, and temporary workspace mounts. Every client reached a fixed point. Complete generated branch ICFGs produced complete results; bounded call-chain, inline, and external ICFGs preserved their typed incomplete status and produced incomplete results rather than false complete negatives.

The largest exploded result was the 512-branch `finite_16` workload: 98,313 reached states and 1,179,940 estimated shallow bytes. Its median first/repeat solves were 31.526/28.001 ms. Repetition was a fresh solve over the same request-local input, not a cache hit. The VS Code process peak was 657.3 MiB while its finite reached result was only 5,136 shallow bytes, showing that process RSS is dominated by workspace construction and must not be presented as result-object size.

The shared artifact-promotion gate was intentionally not invoked: there is no equivalent serialized artifact, hydration path, serialized size, or cache identity to compare. A later reusable summary from #823 must define those semantics and run its own equivalent-artifact matrix before persistence is considered.

## Protocol and provenance

Command, from the Bifrost repository root:

```bash
BIFROST_SEMANTIC_TS_REPO=/Users/dave/Workspace/test-repos/vscode-semantic-cfg \
BIFROST_SEMANTIC_JAVA_REPO=/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg \
  scripts/run-dataflow-lifecycle-benchmarks.sh
```

The runner launched nine fresh locked release processes for each of eight datasets, discarded rounds zero and one for every dataset, retained rounds two through eight, and aggregated 56 JSON samples. `BIFROST_SEMANTIC_INDEX=off` was set for every process. `GIT_OPTIONAL_LOCKS=0` kept sample provenance read-only so `git status` did not refresh the build-script-watched index between processes. Process peak RSS is recorded once per dataset process and repeated in the client-oriented median table only for readability; it is not a per-client allocation measurement.

- Bifrost: `a9daea53dd2f3c654f94e99f2f554e92c86f20b5`, dirty with the reviewed issue changes, tree fingerprint `b01357b912a9f155c36a8ab0aeb461d2fb299def7312ed6b4092c80b9665423d`
- Crate/build: `brokk-bifrost 0.8.10`, release profile
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`, LLVM 22.1.2
- Host: macOS arm64, Darwin 25.5.0, Apple M4, 10 logical CPUs; hostname was deliberately not collected
- Timer: monotonic wall time from `std::time::Instant`
- VS Code: `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, clean; `src/vs/base/common/arrays.ts`, exact `Function(quickSelect)`
- Spring PetClinic: `f182358d02e4a68e52bdbabf55ca7800288511e7`, clean; `OwnerController.java`, exact `Type(OwnerController)::Method(processFindForm)`
- ICFG limits: call depth 8, 50,000 nodes, 200,000 edges
- Clients: production `DirectFlowProblem` and benchmark-only finite workload with exactly 16 facts including zero
- Cache/serialization: `not_applicable_run_local` / unavailable for every client

## Retained medians and stable identities

Times are milliseconds. RSS is the median fresh-process peak in MiB. “Work” is interned facts / reached states / flow evaluations / callback rows / propagated outputs. The shallow-byte estimate covers the result object plus its public fact, reached, and coverage slices; it is not allocator-inclusive retained size.

| Dataset / client | Workspace / semantic / ICFG ms | Solve first / repeat ms | RSS MiB | ICFG nodes / edges / boundaries | Topology SHA-256 | Facts / reached | Work facts / reached / evals / callbacks / outputs | Status / complete | Bytes | Result checksum |
|---|---:|---:|---:|---:|---|---:|---:|---|---:|---:|
| external_spring_petclinic_java / direct | 69.723 / 3.568 / 11.296 | 0.021 / 0.007 | 22.1 | 41 / 41 / 2 | `96f2da6eb25d024c9ffbcc35a5d28cde96cd9931070e6ffa71489367a73e0e75` | 1 / 41 | 1 / 41 / 41 / 42 / 41 | unsupported / false | 940 | 4459160236473380527 |
| external_spring_petclinic_java / finite_16 | 69.723 / 3.568 / 11.296 | 0.141 / 0.125 | 22.1 | 41 / 41 / 2 | `96f2da6eb25d024c9ffbcc35a5d28cde96cd9931070e6ffa71489367a73e0e75` | 16 / 551 | 16 / 551 / 551 / 1076 / 1075 | unsupported / false | 7076 | 2575647176570017997 |
| external_vscode_typescript / direct | 24921.346 / 26.348 / 18.677 | 0.018 / 0.005 | 657.3 | 31 / 30 / 2 | `5473cf4f38fb92e282dfa5a90daba86bde44fb613d60e35b4abf0a3a72d8c04a` | 1 / 31 | 1 / 31 / 30 / 31 / 30 | unknown / false | 812 | 1722895202852227132 |
| external_vscode_typescript / finite_16 | 24921.346 / 26.348 / 18.677 | 0.095 / 0.083 | 657.3 | 31 / 30 / 2 | `5473cf4f38fb92e282dfa5a90daba86bde44fb613d60e35b4abf0a3a72d8c04a` | 16 / 390 | 16 / 390 / 372 / 731 / 730 | unknown / false | 5136 | 3005103082705446891 |
| generated_typescript_branches_512 / direct | 22.233 / 49.838 / 4.011 | 1.227 / 1.071 | 87.5 | 6152 / 6663 / 0 | `eafd32855c811701c59f0cda7505085d656b9e2790e17c01c240b3d727c24472` | 1 / 6152 | 1 / 6152 / 6663 / 6664 / 6663 | complete / true | 73992 | 12411354750699528161 |
| generated_typescript_branches_512 / finite_16 | 22.233 / 49.838 / 4.011 | 31.526 / 28.001 | 87.5 | 6152 / 6663 / 0 | `eafd32855c811701c59f0cda7505085d656b9e2790e17c01c240b3d727c24472` | 16 / 98313 | 16 / 98313 / 106483 / 206323 / 206322 | complete / true | 1179940 | 9847897096946759536 |
| generated_typescript_branches_64 / direct | 12.608 / 5.272 / 0.443 | 0.117 / 0.103 | 26.0 | 776 / 839 / 0 | `56cc501eb4a7af88815174a58df7deca042eede27f101e1c691c1d24b10ac2f8` | 1 / 776 | 1 / 776 / 839 / 840 / 839 | complete / true | 9480 | 272849299080225696 |
| generated_typescript_branches_64 / finite_16 | 12.608 / 5.272 / 0.443 | 2.821 / 2.768 | 26.0 | 776 / 839 / 0 | `56cc501eb4a7af88815174a58df7deca042eede27f101e1c691c1d24b10ac2f8` | 16 / 12297 | 16 / 12297 / 13299 / 25779 / 25778 | complete / true | 147748 | 5695708036881436000 |
| generated_typescript_calls_32 / direct | 12.635 / 3.154 / 10.877 | 0.025 / 0.008 | 20.8 | 53 / 52 / 9 | `ba78c5034b13d4aa55d3701c9cb47db45981a51dae429a8105b1dbc138570205` | 1 / 53 | 1 / 53 / 52 / 53 / 52 | unknown / false | 2028 | 16326939603476035912 |
| generated_typescript_calls_32 / finite_16 | 12.635 / 3.154 / 10.877 | 0.182 / 0.159 | 20.8 | 53 / 52 / 9 | `ba78c5034b13d4aa55d3701c9cb47db45981a51dae429a8105b1dbc138570205` | 16 / 743 | 16 / 743 / 727 / 1417 / 1416 | unknown / false | 10324 | 7806608045215191957 |
| generated_typescript_calls_8 / direct | 11.110 / 1.003 / 4.114 | 0.026 / 0.013 | 20.9 | 85 / 84 / 8 | `79881596e99704abb840c7a96276ea6a214f00c251135a8bf3b526033336bcfc` | 1 / 85 | 1 / 85 / 84 / 85 / 84 | unsupported / false | 2340 | 9437642254504538861 |
| generated_typescript_calls_8 / finite_16 | 11.110 / 1.003 / 4.114 | 0.296 / 0.271 | 20.9 | 85 / 84 / 8 | `79881596e99704abb840c7a96276ea6a214f00c251135a8bf3b526033336bcfc` | 16 / 1255 | 16 / 1255 / 1239 / 2409 / 2408 | unsupported / false | 16396 | 7556780494030992857 |
| inline_java / direct | 10.914 / 0.576 / 1.345 | 0.021 / 0.005 | 17.6 | 23 / 22 / 1 | `ce81bc4290b0160befb77df393803b0b8a9181ef8044e9385f2dce7a1ce04a08` | 1 / 23 | 1 / 23 / 22 / 23 / 22 | unsupported / false | 588 | 14881895776368533640 |
| inline_java / finite_16 | 10.914 / 0.576 / 1.345 | 0.077 / 0.065 | 17.6 | 23 / 22 / 1 | `ce81bc4290b0160befb77df393803b0b8a9181ef8044e9385f2dce7a1ce04a08` | 16 / 260 | 16 / 260 / 241 / 478 / 477 | unsupported / false | 3448 | 4533393618970609491 |
| inline_typescript / direct | 11.423 / 0.557 / 1.041 | 0.017 / 0.005 | 17.8 | 24 / 23 / 2 | `123244d6c6b4afcd37dd1f0d9952e86f2de5d884a0059d28ccc59319301bf679` | 1 / 24 | 1 / 24 / 23 / 24 / 23 | unsupported / false | 736 | 15178303460503179527 |
| inline_typescript / finite_16 | 11.423 / 0.557 / 1.041 | 0.079 / 0.068 | 17.8 | 24 / 23 / 2 | `123244d6c6b4afcd37dd1f0d9952e86f2de5d884a0059d28ccc59319301bf679` | 16 / 276 | 16 / 276 / 257 / 509 / 508 | unsupported / false | 3776 | 2686963774253515667 |

## All retained timing and RSS samples

These are rounds two through eight for every dataset. Solver counts, work, status, completeness, bytes, and checksums were invariant within each group and are therefore shown once in the median table above.

| Dataset | Round | Workspace ms | Semantic ms | ICFG ms | RSS MiB | Direct first/repeat ms | Finite first/repeat ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| external_spring_petclinic_java | 2 | 68.263 | 3.709 | 12.028 | 22.2 | 0.024 / 0.007 | 0.139 / 0.125 |
| external_spring_petclinic_java | 3 | 69.723 | 3.988 | 11.653 | 22.1 | 0.019 / 0.007 | 0.141 / 0.126 |
| external_spring_petclinic_java | 4 | 70.171 | 3.660 | 15.728 | 22.3 | 0.023 / 0.010 | 0.147 / 0.147 |
| external_spring_petclinic_java | 5 | 69.429 | 3.521 | 11.002 | 22.0 | 0.021 / 0.007 | 0.137 / 0.124 |
| external_spring_petclinic_java | 6 | 68.676 | 3.331 | 10.880 | 22.2 | 0.021 / 0.007 | 0.144 / 0.124 |
| external_spring_petclinic_java | 7 | 73.467 | 3.366 | 11.207 | 21.9 | 0.021 / 0.007 | 0.141 / 0.126 |
| external_spring_petclinic_java | 8 | 72.282 | 3.568 | 11.296 | 22.0 | 0.021 / 0.007 | 0.141 / 0.125 |
| external_vscode_typescript | 2 | 22276.512 | 26.034 | 18.616 | 657.3 | 0.023 / 0.006 | 0.096 / 0.083 |
| external_vscode_typescript | 3 | 22759.654 | 25.830 | 18.123 | 658.7 | 0.018 / 0.005 | 0.095 / 0.087 |
| external_vscode_typescript | 4 | 25184.787 | 26.348 | 18.846 | 658.6 | 0.018 / 0.006 | 0.092 / 0.082 |
| external_vscode_typescript | 5 | 24921.346 | 27.619 | 19.480 | 656.6 | 0.015 / 0.005 | 0.092 / 0.082 |
| external_vscode_typescript | 6 | 26633.914 | 26.472 | 18.441 | 651.1 | 0.017 / 0.006 | 0.096 / 0.085 |
| external_vscode_typescript | 7 | 23905.647 | 26.587 | 19.240 | 658.1 | 0.017 / 0.005 | 0.099 / 0.082 |
| external_vscode_typescript | 8 | 29192.209 | 25.985 | 18.677 | 657.3 | 0.018 / 0.005 | 0.093 / 0.084 |
| generated_typescript_branches_512 | 2 | 21.383 | 46.832 | 2.931 | 87.5 | 0.852 / 0.800 | 31.526 / 28.001 |
| generated_typescript_branches_512 | 3 | 21.678 | 46.591 | 3.390 | 88.7 | 1.030 / 0.933 | 32.530 / 27.676 |
| generated_typescript_branches_512 | 4 | 22.233 | 49.838 | 4.710 | 90.2 | 1.427 / 1.409 | 23.828 / 24.054 |
| generated_typescript_branches_512 | 5 | 52.036 | 93.556 | 4.246 | 87.4 | 1.227 / 1.270 | 39.245 / 37.327 |
| generated_typescript_branches_512 | 6 | 44.714 | 71.088 | 4.754 | 88.3 | 1.433 / 1.336 | 28.749 / 30.519 |
| generated_typescript_branches_512 | 7 | 25.179 | 55.103 | 4.011 | 87.2 | 1.355 / 1.071 | 32.970 / 38.410 |
| generated_typescript_branches_512 | 8 | 18.286 | 39.655 | 2.734 | 87.5 | 0.839 / 0.849 | 24.677 / 23.954 |
| generated_typescript_branches_64 | 2 | 13.109 | 5.371 | 0.451 | 26.0 | 0.119 / 0.101 | 2.791 / 2.711 |
| generated_typescript_branches_64 | 3 | 11.923 | 5.272 | 0.448 | 25.8 | 0.116 / 0.102 | 2.894 / 2.786 |
| generated_typescript_branches_64 | 4 | 12.608 | 5.183 | 0.405 | 25.9 | 0.115 / 0.105 | 2.816 / 2.744 |
| generated_typescript_branches_64 | 5 | 12.379 | 5.301 | 0.443 | 26.0 | 0.117 / 0.103 | 2.776 / 2.713 |
| generated_typescript_branches_64 | 6 | 13.001 | 5.202 | 0.421 | 25.9 | 0.115 / 0.118 | 2.821 / 3.023 |
| generated_typescript_branches_64 | 7 | 12.779 | 5.184 | 0.406 | 26.2 | 0.118 / 0.101 | 3.003 / 3.071 |
| generated_typescript_branches_64 | 8 | 12.354 | 5.314 | 0.609 | 26.3 | 0.156 / 0.130 | 3.318 / 2.768 |
| generated_typescript_calls_32 | 2 | 12.521 | 3.185 | 10.525 | 20.8 | 0.025 / 0.008 | 0.176 / 0.155 |
| generated_typescript_calls_32 | 3 | 13.462 | 3.233 | 10.814 | 20.7 | 0.028 / 0.008 | 0.177 / 0.185 |
| generated_typescript_calls_32 | 4 | 12.812 | 3.154 | 10.894 | 20.7 | 0.028 / 0.008 | 0.170 / 0.169 |
| generated_typescript_calls_32 | 5 | 13.210 | 3.123 | 10.877 | 20.7 | 0.025 / 0.008 | 0.182 / 0.159 |
| generated_typescript_calls_32 | 6 | 12.129 | 3.210 | 10.961 | 20.8 | 0.025 / 0.008 | 0.195 / 0.163 |
| generated_typescript_calls_32 | 7 | 12.216 | 3.045 | 11.842 | 20.9 | 0.025 / 0.010 | 0.184 / 0.156 |
| generated_typescript_calls_32 | 8 | 12.635 | 3.125 | 10.646 | 20.8 | 0.025 / 0.008 | 0.184 / 0.155 |
| generated_typescript_calls_8 | 2 | 10.849 | 0.990 | 4.135 | 21.0 | 0.026 / 0.013 | 0.286 / 0.268 |
| generated_typescript_calls_8 | 3 | 11.070 | 1.003 | 3.952 | 20.9 | 0.025 / 0.013 | 0.296 / 0.268 |
| generated_typescript_calls_8 | 4 | 11.672 | 0.981 | 4.150 | 20.8 | 0.025 / 0.013 | 0.290 / 0.293 |
| generated_typescript_calls_8 | 5 | 10.924 | 1.009 | 4.379 | 20.8 | 0.026 / 0.014 | 0.294 / 0.271 |
| generated_typescript_calls_8 | 6 | 11.481 | 0.997 | 4.059 | 20.8 | 0.026 / 0.013 | 0.314 / 0.311 |
| generated_typescript_calls_8 | 7 | 11.952 | 1.009 | 4.021 | 20.9 | 0.026 / 0.013 | 0.431 / 0.299 |
| generated_typescript_calls_8 | 8 | 11.110 | 1.036 | 4.114 | 20.9 | 0.025 / 0.013 | 0.296 / 0.269 |
| inline_java | 2 | 10.832 | 0.576 | 1.353 | 17.7 | 0.025 / 0.005 | 0.077 / 0.065 |
| inline_java | 3 | 10.616 | 0.594 | 1.345 | 17.6 | 0.022 / 0.005 | 0.083 / 0.064 |
| inline_java | 4 | 10.912 | 0.520 | 1.251 | 17.7 | 0.019 / 0.005 | 0.073 / 0.064 |
| inline_java | 5 | 10.914 | 0.557 | 1.310 | 17.5 | 0.015 / 0.005 | 0.073 / 0.066 |
| inline_java | 6 | 11.130 | 0.577 | 1.342 | 17.5 | 0.021 / 0.005 | 0.078 / 0.068 |
| inline_java | 7 | 11.176 | 0.566 | 1.362 | 17.7 | 0.024 / 0.006 | 0.077 / 0.066 |
| inline_java | 8 | 11.144 | 0.588 | 1.355 | 17.5 | 0.020 / 0.005 | 0.077 / 0.063 |
| inline_typescript | 2 | 11.021 | 0.631 | 1.223 | 17.8 | 0.017 / 0.007 | 0.081 / 0.067 |
| inline_typescript | 3 | 11.807 | 0.623 | 1.041 | 17.8 | 0.020 / 0.005 | 0.079 / 0.070 |
| inline_typescript | 4 | 10.816 | 0.652 | 1.064 | 17.8 | 0.017 / 0.005 | 0.076 / 0.070 |
| inline_typescript | 5 | 10.680 | 0.526 | 0.937 | 17.9 | 0.015 / 0.005 | 0.077 / 0.068 |
| inline_typescript | 6 | 11.423 | 0.545 | 1.279 | 17.7 | 0.019 / 0.005 | 0.139 / 0.081 |
| inline_typescript | 7 | 13.245 | 0.557 | 1.005 | 17.8 | 0.015 / 0.007 | 0.081 / 0.068 |
| inline_typescript | 8 | 11.868 | 0.533 | 0.972 | 17.8 | 0.015 / 0.005 | 0.077 / 0.068 |

The raw v2 runner aggregate was 151,174 bytes and contained the same 56 full JSON samples plus the median rows above. It was used to generate this checked-in report; the temporary aggregate itself is not a product artifact.
