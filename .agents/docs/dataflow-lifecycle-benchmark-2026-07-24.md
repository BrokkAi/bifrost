# Bounded data-flow artifact lifecycle benchmark — 2026-07-24

This report records the issue #817 lifecycle decision for the current bounded exploded data-flow state. It measures request-local ICFG construction and two solver clients; it does not construct a serialized candidate because concrete seeds, run-local fact IDs, worklists, truncations, and reached results are not reusable procedure summaries.

## Decision

**Recommendation: `ephemeral_not_eligible; persist reusable summaries only after #823 defines and measures them`.**

All 56 retained samples reproduced identical dataset provenance, ICFG topology and semantic work, client fact/reached counts, five solver-work counters, termination, completeness, shallow retained bytes, and result checksums. Every client reached a fixed point. Complete generated branch ICFGs produced complete results; bounded call-chain, inline, and external ICFGs preserved their typed incomplete status and produced incomplete results rather than false complete negatives.

The largest exploded result was the 512-branch `finite_16` workload: 98,313 reached states and 1,179,940 estimated shallow bytes. Its median first/repeat solves were 34.512/63.640 ms. Repetition was a fresh solve over the same request-local input, not a cache hit. The VS Code process peak was 659.0 MiB while its finite reached result was only 5,136 shallow bytes, showing that process RSS is dominated by workspace construction and must not be presented as result-object size.

The shared artifact-promotion gate was intentionally not invoked: there is no equivalent serialized artifact, hydration path, serialized size, or cache identity to compare. A later reusable summary from #823 must define those semantics and run its own equivalent-artifact matrix before persistence is considered.

## Protocol and provenance

Command, from the Bifrost repository root:

```bash
BIFROST_SEMANTIC_TS_REPO=/Users/dave/Workspace/test-repos/vscode-semantic-cfg \
BIFROST_SEMANTIC_JAVA_REPO=/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg \
  scripts/run-dataflow-lifecycle-benchmarks.sh
```

The runner launched nine fresh release processes for each of eight datasets, discarded rounds zero and one for every dataset, retained rounds two through eight, and aggregated 56 JSON samples. `BIFROST_SEMANTIC_INDEX=off` was set for every process. Process peak RSS is recorded once per dataset process and repeated in the client-oriented median table only for readability; it is not a per-client allocation measurement.

- Bifrost: `da37cbc839081bba1d86dd27684fec283940ae28`, clean, tree fingerprint `99d580ca9c8c50f83343b784afdc69be589a2acab5d3f94773a53526cd4f706c`
- Crate/build: `brokk-bifrost 0.8.10`, release profile
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`, LLVM 22.1.2
- Host: macOS arm64, Darwin 25.5.0, 10 logical CPUs; CPU-model lookup was unavailable
- Timer: monotonic wall time from `std::time::Instant`
- VS Code: `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, clean; `src/vs/base/common/arrays.ts`, exact `Function(quickSelect)`
- Spring PetClinic: `f182358d02e4a68e52bdbabf55ca7800288511e7`, clean; `OwnerController.java`, exact `Type(OwnerController)::Method(processFindForm)`
- ICFG limits: call depth 8, 50,000 nodes, 200,000 edges
- Clients: production `DirectFlowProblem` and benchmark-only finite workload with exactly 16 facts including zero
- Cache/serialization: `not_applicable_run_local` / unavailable for every client

## Retained medians and stable identities

Times are milliseconds. RSS is the median fresh-process peak in MiB. “Work” is interned facts / reached states / flow evaluations / callback rows / propagated outputs. The shallow-byte estimate covers the result object plus its public fact, reached, and coverage slices; it is not allocator-inclusive retained size.

| Dataset / client | Workspace / semantic / ICFG ms | Solve first / repeat ms | RSS MiB | ICFG nodes / edges / boundaries | Facts / reached | Work facts / reached / evals / callbacks / outputs | Status / complete | Bytes | Checksum |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| external_spring_petclinic_java / direct | 183.601 / 10.334 / 41.376 | 0.026 / 0.007 | 21.5 | 41 / 41 / 2 | 1 / 41 | 1 / 41 / 41 / 42 / 41 | unsupported / false | 940 | 8862284132134275048 |
| external_spring_petclinic_java / finite_16 | 183.601 / 10.334 / 41.376 | 0.138 / 0.126 | 21.5 | 41 / 41 / 2 | 16 / 551 | 16 / 551 / 551 / 1076 / 1075 | unsupported / false | 7076 | 18154118344030636796 |
| external_vscode_typescript / direct | 33512.965 / 33.788 / 23.610 | 0.023 / 0.006 | 659.0 | 31 / 30 / 2 | 1 / 31 | 1 / 31 / 30 / 31 / 30 | unknown / false | 812 | 18214206341767704809 |
| external_vscode_typescript / finite_16 | 33512.965 / 33.788 / 23.610 | 0.093 / 0.083 | 659.0 | 31 / 30 / 2 | 16 / 390 | 16 / 390 / 372 / 731 / 730 | unknown / false | 5136 | 1249601727928353037 |
| generated_typescript_branches_512 / direct | 18.976 / 49.723 / 1.632 | 0.463 / 0.434 | 34.9 | 6152 / 6663 / 0 | 1 / 6152 | 1 / 6152 / 6663 / 6664 / 6663 | complete / true | 73992 | 17031623719389330401 |
| generated_typescript_branches_512 / finite_16 | 18.976 / 49.723 / 1.632 | 34.512 / 63.640 | 34.9 | 6152 / 6663 / 0 | 16 / 98313 | 16 / 98313 / 106483 / 206323 / 206322 | complete / true | 1179940 | 3149839785587667984 |
| generated_typescript_branches_64 / direct | 10.997 / 5.976 / 0.544 | 0.154 / 0.132 | 19.3 | 776 / 839 / 0 | 1 / 776 | 1 / 776 / 839 / 840 / 839 | complete / true | 9480 | 14770342949475302118 |
| generated_typescript_branches_64 / finite_16 | 10.997 / 5.976 / 0.544 | 3.024 / 1.527 | 19.3 | 776 / 839 / 0 | 16 / 12297 | 16 / 12297 / 13299 / 25779 / 25778 | complete / true | 147748 | 9941097766616935309 |
| generated_typescript_calls_32 / direct | 13.037 / 2.755 / 13.854 | 0.021 / 0.004 | 18.6 | 53 / 52 / 9 | 1 / 53 | 1 / 53 / 52 / 53 / 52 | unknown / false | 2028 | 6411815615594076246 |
| generated_typescript_calls_32 / finite_16 | 13.037 / 2.755 / 13.854 | 0.092 / 0.082 | 18.6 | 53 / 52 / 9 | 16 / 743 | 16 / 743 / 727 / 1417 / 1416 | unknown / false | 10324 | 48444760638508871 |
| generated_typescript_calls_8 / direct | 10.628 / 1.264 / 5.217 | 0.036 / 0.007 | 17.9 | 85 / 84 / 8 | 1 / 85 | 1 / 85 / 84 / 85 / 84 | unsupported / false | 2340 | 1012845517010923369 |
| generated_typescript_calls_8 / finite_16 | 10.628 / 1.264 / 5.217 | 0.160 / 0.144 | 17.9 | 85 / 84 / 8 | 16 / 1255 | 16 / 1255 / 1239 / 2409 / 2408 | unsupported / false | 16396 | 10567677753392813135 |
| inline_java / direct | 30.961 / 0.819 / 2.478 | 0.029 / 0.006 | 17.3 | 23 / 22 / 1 | 1 / 23 | 1 / 23 / 22 / 23 / 22 | unsupported / false | 588 | 621847044399286051 |
| inline_java / finite_16 | 30.961 / 0.819 / 2.478 | 0.093 / 0.082 | 17.3 | 23 / 22 / 1 | 16 / 260 | 16 / 260 / 241 / 478 / 477 | unsupported / false | 3448 | 4319779334050046862 |
| inline_typescript / direct | 29.180 / 0.734 / 2.908 | 0.029 / 0.006 | 17.6 | 24 / 23 / 2 | 1 / 24 | 1 / 24 / 23 / 24 / 23 | unsupported / false | 736 | 11218546533244378642 |
| inline_typescript / finite_16 | 29.180 / 0.734 / 2.908 | 0.089 / 0.084 | 17.6 | 24 / 23 / 2 | 16 / 276 | 16 / 276 / 257 / 509 / 508 | unsupported / false | 3776 | 3129573660448584592 |

## All retained timing and RSS samples

These are rounds two through eight for every dataset. Solver counts, work, status, completeness, bytes, and checksums were invariant within each group and are therefore shown once in the median table above.

| Dataset | Round | Workspace ms | Semantic ms | ICFG ms | RSS MiB | Direct first/repeat ms | Finite first/repeat ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| external_spring_petclinic_java | 2 | 183.601 | 44.693 | 36.457 | 21.5 | 0.028 / 0.009 | 0.172 / 0.163 |
| external_spring_petclinic_java | 3 | 126.656 | 4.452 | 18.672 | 21.4 | 0.026 / 0.007 | 0.137 / 0.126 |
| external_spring_petclinic_java | 4 | 787.394 | 168.332 | 12.455 | 21.5 | 0.025 / 0.008 | 0.159 / 0.145 |
| external_spring_petclinic_java | 5 | 252.703 | 13.011 | 108.006 | 21.3 | 0.026 / 0.007 | 0.136 / 0.122 |
| external_spring_petclinic_java | 6 | 172.414 | 3.914 | 41.376 | 21.5 | 0.025 / 0.007 | 0.137 / 0.123 |
| external_spring_petclinic_java | 7 | 171.683 | 3.899 | 135.942 | 21.4 | 0.029 / 0.010 | 22.690 / 1.063 |
| external_spring_petclinic_java | 8 | 195.863 | 10.334 | 71.187 | 21.5 | 0.024 / 0.007 | 0.138 / 0.125 |
| external_vscode_typescript | 2 | 22134.763 | 25.079 | 17.706 | 659.0 | 0.022 / 0.005 | 0.093 / 0.081 |
| external_vscode_typescript | 3 | 33512.965 | 33.788 | 59.439 | 659.2 | 0.023 / 0.006 | 0.096 / 0.083 |
| external_vscode_typescript | 4 | 35901.256 | 25.163 | 17.699 | 659.1 | 0.023 / 0.005 | 0.091 / 0.082 |
| external_vscode_typescript | 5 | 22721.999 | 25.141 | 17.376 | 658.8 | 0.024 / 0.005 | 0.091 / 0.083 |
| external_vscode_typescript | 6 | 33660.557 | 35.195 | 23.610 | 658.7 | 0.028 / 0.007 | 0.118 / 0.111 |
| external_vscode_typescript | 7 | 37508.580 | 64.014 | 26.174 | 658.3 | 0.025 / 0.006 | 0.105 / 0.094 |
| external_vscode_typescript | 8 | 31268.945 | 340.861 | 79.582 | 659.3 | 0.022 / 0.006 | 0.093 / 0.082 |
| generated_typescript_branches_512 | 2 | 23.290 | 30.013 | 1.559 | 35.4 | 0.459 / 0.436 | 16.221 / 17.774 |
| generated_typescript_branches_512 | 3 | 19.026 | 58.531 | 1.632 | 35.6 | 0.465 / 0.434 | 25.548 / 49.877 |
| generated_typescript_branches_512 | 4 | 20.322 | 139.033 | 1.596 | 34.9 | 0.476 / 9.021 | 34.512 / 63.640 |
| generated_typescript_branches_512 | 5 | 17.703 | 49.723 | 2.437 | 34.3 | 0.460 / 1.201 | 22.241 / 210.251 |
| generated_typescript_branches_512 | 6 | 16.235 | 39.194 | 1.621 | 34.9 | 0.477 / 0.430 | 49.784 / 181.489 |
| generated_typescript_branches_512 | 7 | 17.176 | 75.070 | 3.014 | 34.8 | 0.450 / 0.419 | 36.652 / 70.351 |
| generated_typescript_branches_512 | 8 | 18.976 | 37.824 | 2.779 | 36.8 | 0.463 / 0.428 | 45.186 / 22.620 |
| generated_typescript_branches_64 | 2 | 10.997 | 6.222 | 0.544 | 19.2 | 0.154 / 0.133 | 3.024 / 1.527 |
| generated_typescript_branches_64 | 3 | 21.197 | 5.861 | 0.303 | 19.0 | 0.071 / 0.054 | 1.478 / 1.462 |
| generated_typescript_branches_64 | 4 | 14.273 | 6.210 | 0.634 | 19.4 | 0.163 / 0.195 | 4.756 / 3.325 |
| generated_typescript_branches_64 | 5 | 9.254 | 5.976 | 0.593 | 19.4 | 0.185 / 0.139 | 4.214 / 6.410 |
| generated_typescript_branches_64 | 6 | 9.218 | 4.378 | 0.278 | 19.3 | 0.069 / 0.054 | 1.472 / 1.437 |
| generated_typescript_branches_64 | 7 | 14.794 | 2.859 | 0.260 | 19.0 | 0.068 / 0.054 | 1.510 / 1.476 |
| generated_typescript_branches_64 | 8 | 9.353 | 6.484 | 0.551 | 19.3 | 0.158 / 0.132 | 3.660 / 4.062 |
| generated_typescript_calls_32 | 2 | 9.990 | 2.755 | 13.854 | 18.7 | 0.021 / 0.005 | 0.092 / 0.085 |
| generated_typescript_calls_32 | 3 | 10.251 | 3.805 | 10.042 | 18.5 | 0.021 / 0.004 | 0.093 / 0.081 |
| generated_typescript_calls_32 | 4 | 13.037 | 5.519 | 5.844 | 18.5 | 0.016 / 0.004 | 0.089 / 0.082 |
| generated_typescript_calls_32 | 5 | 10.597 | 2.369 | 10.089 | 18.7 | 0.028 / 0.010 | 0.199 / 0.246 |
| generated_typescript_calls_32 | 6 | 20.848 | 1.738 | 31.675 | 18.6 | 0.019 / 0.005 | 0.092 / 0.082 |
| generated_typescript_calls_32 | 7 | 13.570 | 2.554 | 17.036 | 18.7 | 0.022 / 0.004 | 0.094 / 0.086 |
| generated_typescript_calls_32 | 8 | 25.263 | 3.241 | 14.358 | 18.6 | 0.017 / 0.004 | 0.091 / 0.081 |
| generated_typescript_calls_8 | 2 | 17.146 | 2.138 | 6.119 | 17.9 | 0.022 / 0.007 | 0.153 / 0.141 |
| generated_typescript_calls_8 | 3 | 14.612 | 0.736 | 2.412 | 18.0 | 0.045 / 0.007 | 0.160 / 0.144 |
| generated_typescript_calls_8 | 4 | 6.705 | 0.587 | 2.261 | 17.9 | 0.018 / 0.007 | 0.151 / 0.139 |
| generated_typescript_calls_8 | 5 | 9.699 | 1.264 | 5.303 | 17.9 | 0.036 / 0.016 | 0.337 / 0.320 |
| generated_typescript_calls_8 | 6 | 10.628 | 0.590 | 2.558 | 17.9 | 0.019 / 0.007 | 0.152 / 0.142 |
| generated_typescript_calls_8 | 7 | 20.337 | 1.294 | 6.459 | 17.9 | 0.037 / 0.016 | 0.388 / 0.319 |
| generated_typescript_calls_8 | 8 | 9.065 | 1.264 | 5.217 | 17.9 | 0.036 / 0.016 | 0.333 / 0.316 |
| inline_java | 2 | 36.550 | 0.802 | 2.647 | 17.4 | 0.026 / 0.006 | 0.093 / 0.080 |
| inline_java | 3 | 25.056 | 0.799 | 8.054 | 17.3 | 0.034 / 0.006 | 0.101 / 0.084 |
| inline_java | 4 | 31.974 | 3.721 | 8.404 | 17.3 | 0.029 / 0.007 | 0.104 / 0.099 |
| inline_java | 5 | 33.273 | 1.059 | 2.380 | 17.3 | 0.030 / 0.006 | 0.086 / 0.077 |
| inline_java | 6 | 16.573 | 0.863 | 2.478 | 17.4 | 0.025 / 0.005 | 0.082 / 0.073 |
| inline_java | 7 | 30.961 | 0.819 | 2.133 | 17.3 | 0.026 / 0.006 | 0.092 / 0.082 |
| inline_java | 8 | 22.792 | 0.692 | 2.010 | 17.2 | 0.038 / 0.005 | 0.117 / 0.110 |
| inline_typescript | 2 | 25.193 | 0.624 | 1.285 | 17.6 | 0.022 / 0.006 | 0.089 / 0.087 |
| inline_typescript | 3 | 179.754 | 77.042 | 1.766 | 17.6 | 0.029 / 0.009 | 0.105 / 0.096 |
| inline_typescript | 4 | 34.320 | 1.915 | 3.080 | 17.6 | 0.030 / 0.006 | 0.092 / 0.084 |
| inline_typescript | 5 | 29.180 | 0.703 | 1.549 | 17.4 | 0.024 / 0.006 | 0.087 / 0.084 |
| inline_typescript | 6 | 22.572 | 0.734 | 5.206 | 17.6 | 0.026 / 0.008 | 0.083 / 0.077 |
| inline_typescript | 7 | 29.075 | 0.619 | 2.908 | 17.6 | 0.030 / 0.010 | 0.095 / 0.087 |
| inline_typescript | 8 | 36.245 | 0.748 | 3.183 | 17.6 | 0.029 / 0.006 | 0.088 / 0.080 |

The raw runner aggregate was 152,434 bytes and contained the same 56 full JSON samples plus the median rows above. It was used to generate this checked-in report; the temporary aggregate itself is not a product artifact.
