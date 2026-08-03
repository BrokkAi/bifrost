# Ruby dependency pack measurement for issue #1351

This note records a bounded regression baseline for the executable fixture in
`tests/suite_semantic/ruby_dependency_semantic_pack.rs`. It is not a production
benchmark and does not generalize to arbitrary gems.

## Fixture

- Debug build on the issue worktree at commit `20b78e37a` plus the measurement
  field added immediately afterward.
- One synthetic `.gem` with an outer tar and compressed `data.tar.gz`.
- Three declaration entries: one RBS, one RBI, and one ordinary Ruby source.
- Four types and three members after deterministic cross-origin merging.
- Ephemeral semantic-pack catalog, with a cold generation followed by a warm
  lookup of the identical evidence and artifact bytes.

## Result

The representative test command is:

    cargo test --test suite_semantic ruby_dependency_semantic_pack -- --nocapture

The recorded representative run reported:

| Metric | Value |
| --- | ---: |
| Artifact bytes read | 2,048 |
| Compiled stored bytes | 1,219 |
| Produced declaration facts | 7 |
| Active retained bytes | 6,432 |
| Discovery | 458 us |
| Cold generation and installation | 22,425 us |
| Warm catalog reuse | 1,396 us |

The executable test prints the same fields, including compiled stored bytes
from catalog accounting. Timing varies with incremental build and host load;
compare future runs by shape and order of magnitude, and investigate sustained
regressions rather than treating one microsecond value as a gate.

## Boundaries

The byte count is the exact archive input charged by dependency preparation.
The retained-byte value is the active semantic runtime's lower-bound
accounting. Cold time includes bounded archive reading, parsing, canonical
compilation, and ephemeral catalog installation. Warm time repeats exact
discovery and preparation against the populated catalog. No Ruby executable,
Bundler process, network access, gem-cache scan, or archive extraction occurs.
