# brokk-bifrost-flow

Flow-analysis implementation crate for Bifrost. It owns the dataflow,
value-flow, taint, and typestate engines and their reusable workspace state.

Most consumers should depend on the `brokk-bifrost` facade instead.

## Dependency source derivation

Dependency behavior derivation is a fallback for a missing, requested summary
partition. A caller first selects the exact dependency artifact, version, and
profile, then checks applicable installed and configured fetchable semantic
packs through the existing catalog and acquisition path. A pack that supplies
the requested partition takes precedence over parsing implementation bodies.
Cheap declaration discovery needed for artifact identity does not imply that
source behavior must be derived.

If a pack is partial, retain its established facts and derive only the missing
partition from an exact immutable source snapshot. Fetch failure, unavailable
source, incompatibility, and offline mode are distinct caller outcomes. The
flow crate neither resolves packages nor fetches packs. A positive normal-result
relation can survive incomplete analysis; an empty relation certifies absence
only within an independently exhaustive source/result partition. Normal-result
evidence does not establish exceptional, heap, callback, mutation, or effect
behavior.
