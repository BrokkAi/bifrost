# Semantic oracle lifecycle benchmark — 2026-07-21

This note records the Milestone 7 measurement for issue #816. It covers generation-local semantic-artifact reuse, disk and overlay invalidation, request-local value/heap projection growth, receiver-query compatibility overhead, and one non-reference-language pressure test. It does not benchmark an IFDS/IDE solver, an FSA client, reusable procedure summaries, or a persistence implementation.

## Reproduction and provenance

The checked-in ignored release test is `tests/measure_semantic_oracles.rs`; `scripts/run-semantic-oracle-benchmarks.sh` validates the external repositories, runs two warmups plus five retained samples, and prints one aggregate JSON record prefixed by `BIFROST_SEMANTIC_ORACLE_BENCHMARK=`.

The retained matrix used:

- Bifrost HEAD `953e434296a5410c1019cfe3d815e77edba25f3c` plus dirty-tree fingerprint `769ea15f05cd2c6756e6855968790caf3c3d5747a045a3b03cbbcc40f213a527`.
- Rust `1.96.0 (ac68faa20 2026-05-25)`, release profile, `aarch64-apple-darwin`, macOS, 10 reported logical CPUs.
- VS Code `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, clean.
- Spring PetClinic `f182358d02e4a68e52bdbabf55ca7800288511e7`, clean.
- Retained rounds `2, 3, 4, 5, 6`; wall-clock medians use `std::time::Instant`.
- Per-dataset caps of 4,096 points-to/location value observations and 1,024 alias observations. A cap is recorded independently from an oracle result-set truncation.

Run from the repository root with the rustup toolchain selected:

    BIFROST_SEMANTIC_TS_REPO=/path/to/pinned/vscode \
    BIFROST_SEMANTIC_JAVA_REPO=/path/to/pinned/spring-petclinic \
      scripts/run-semantic-oracle-benchmarks.sh

## Median timings and reuse

| Dataset | Files materialized | Cold materialization | Immediate whole-corpus repeat | Exact `Arc` reuse | Oracle projection | Structural call baseline | Receiver projection | Receiver overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Inline TypeScript | 1 | 0.543 ms | 0.065 ms | 1 / 1 | 10.892 ms | 0.171 ms | 0.435 ms | 0.267 ms |
| Inline Java | 1 | 0.487 ms | 0.069 ms | 1 / 1 | 9.710 ms | 0.189 ms | 1.175 ms | 0.986 ms |
| VS Code TypeScript | 5,625 of 5,633 | 23,379.198 ms | 22,683.799 ms | 460 / 5,625 (8.2%) | 2,436.735 ms | 195.769 ms | 1,070.099 ms | 873.636 ms |
| Spring PetClinic Java | 49 | 37.305 ms | 7.078 ms | 49 / 49 | 1,173.726 ms | 4.612 ms | 318.877 ms | 314.186 ms |

The inline and PetClinic working sets fit the byte-bounded generation cache and reuse every complete artifact. The 5,625-artifact VS Code sweep does not fit: iterating the same order immediately afterward evicts entries ahead of the scan, so only a median 460 artifacts retain pointer identity and the whole-corpus repeat remains nearly cold. This is bounded-cache behavior, not a stale-key failure. Single-file disk and overlay updates both produced new artifact keys, then reused the new complete artifact on the next request.

The receiver timing deliberately compares a 200-result structural call query with the same query plus the compatibility projection. It is a broad pipeline stress measurement, not the latency of one already-selected receiver. The TypeScript and Java corpus queries hit the structural result limit and therefore report `truncated`; they must not be read as exhaustive receiver coverage. The result counts were 200 structural rows to 1 receiver row for the selected VS Code prefix and 200 to 200 for PetClinic, with 0 and 52 retained neutral value candidates respectively.

## Finite growth observations

| Dataset | Procedures | Value-flow relations | Max relations / procedure | Max points-to candidates | Max location candidates | Max alias breadth | Max access-path length | Summary-tailed paths | Retained provenance handles | Result sets truncated |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Inline TypeScript | 4 | 44 | 23 | 2 | 2 | 2 | 1 | 0 | 498 | 0 |
| Inline Java | 4 | 46 | 21 | 2 | 2 | 2 | 1 | 0 | 499 | 0 |
| VS Code TypeScript | 118,080 | 1,827,149 | 1,314 | 4 | 4 | 4 | 1 | 0 | 1,837,719 | 0 |
| Spring PetClinic Java | 227 | 1,416 | 81 | 2 | 2 | 2 | 1 | 0 | 9,482 | 0 |

The external TypeScript value-observation and alias loops reached their explicit query caps, and the Java alias loop reached its cap. Those caps bound how much of the corpus the measurement asks about; they did not truncate any individual oracle candidate set. Every observed access path remained exact and at most one selector long. Longer and summary-tailed paths remain covered by adversarial contract tests rather than being inferred from their absence in these corpora.

The high count of open answers is expected from real adapter gaps and open-world dispatch: 126,182 open sets in VS Code and 6,221 in PetClinic. The measurement therefore confirms that uncertainty remains explicit under corpus load instead of turning sparse candidates into exhaustive claims.

## Invalidation and incomplete work

Across five retained samples:

- Disk update plus rematerialization median: 0.767 ms.
- Overlay update plus rematerialization median: 0.639 ms.
- Every disk and overlay source change changed the complete artifact key.
- Every immediately repeated post-update request reused the new complete `Arc`.
- A cancelled materialization was always followed successfully by a complete materialization; incomplete work did not populate the complete cache.

## Portability pressure and defects found

A Rust control-only adapter was queried through the same neutral value and heap interfaces. It returns empty `Open` relation/candidate sets rather than falsely exhaustive emptiness when value, allocation, and memory capabilities are unavailable. This keeps non-reference adapters behind the neutral boundary without adding a language branch to the oracle.

The pinned VS Code scan found two source-backed soundness defects that the inline fixtures had not exposed:

1. A nested arrow could publish a receiver capture slot when its parent did not actually lower the callable-creation event. Child capture completeness now depends on an already-emitted parent `CaptureBinding`; an unbound slot carries an explicit `Captures` gap.
2. Assignment to a formal parameter is a valid `value -> parameter` relation, but the projection assumed the parameter was always the source. Parameter ports now preserve both read and write direction.

Both fixes have focused behavior tests. They use emitted IR and structured AST lowering only; no text scan or language-specific oracle branch was added.

## Rollout decision

Retain complete semantic artifacts in the existing byte-bounded generation-local memory cache. Keep value-flow, heap, alias, and receiver projections request-local. Do not add SQLite persistence under #816.

The matrix shows that a full VS Code semantic working set exceeds the current in-memory cache and that broad receiver/oracle projections are nontrivial. It does not show that serializing raw per-file semantic artifacts or request-owned relation arenas would be a net win: no packed storage representation, write amplification, hydration cost, invalidation protocol, or cross-generation reuse gate was measured here. Reusable client-independent or solver summaries remain the more plausible future persistence candidate and belong to the separately measured #817/#823 lifecycle work.

The next architecture step may consume these finite relations in #819/#820 without changing their ownership: graph utilities and solver worklists remain clients; oracle arenas remain bounded evidence for one exact query and generation.
