# Issue 1352 Rust dependency pack measurement

Measured on 2026-08-02 with the offline
`rust_dependency_semantic_pack::exact_cargo_evidence_activates_registry_git_and_path_dependency_apis`
integration fixture. The fixture contains one registry dependency, one git
dependency, and one external path dependency. It is intentionally small and is
evidence for phase shape and cache behavior, not a production performance
threshold.

The fixture has 8,390 rustdoc JSON input bytes, 21 decoded rustdoc items, and
produces 25 declaration facts: 11 types, 8 members, and 6 relations. The active
model reports a 21,668-byte retained estimate.

Five warm-process repetitions reported:

| Phase | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Discovery | 2.122 ms | 2.177 ms | 18.369 ms |
| Cold generation | 121.843 ms | 135.884 ms | 187.115 ms |
| Warm catalog reuse | 3.896 ms | 4.189 ms | 11.229 ms |

The test prints a machine-readable `rust_dependency_pack_measurement={...}`
record under `--nocapture`. Cold generation includes exact-artifact reads,
rustdoc decoding, projection, compilation, and ephemeral-catalog installation.
Warm reuse repeats preparation against the same catalog and verifies all three
productions report `Reused`. Discovery is measured separately. No operation
approached the repository's five-second interactive-latency issue threshold.
