Synthetic rustdoc format-61 documents for the selected SQLx facade join.
Written for this test fixture; no SQLx or premium source is copied here.
The analyzer reads the JSON only. Do not build or execute these documents as crates.

`facade-public.json` has a root-public explicit `Use` whose structured target
is `sqlx_core::query::query` (external rustdoc item 100). Its rendered
`Use.source` deliberately disagrees. `core-v1.json` and `core-v2.json` publish
identically named functions with different package versions: only a selected
Cargo resolve edge to the exact version may join. Feature-set and removed-edge
negatives reuse these documents with different selected evidence.

`facade-missing.json` has no re-export. `facade-private.json` has a crate-visible
`Use`, which must not license a public call. `facade-shadowed.json` has a local
`query` function and a glob import; the explicit local item wins. A MaD row
spelling `sqlx.query` or a synthetic alias must not substitute for the absent
edge in the missing fixture.

`facade-glob.json` selects the external `sqlx_core::query` module by a public
Rustdoc glob. `facade-two-globs.json` has two globs for the same exported name
and must abstain. `facade-inlined.json` has a foreign-owned item copied into the
facade's root index; its original path still identifies `sqlx_core`.
`facade-private-module.json` places a public Use below a private module and
must abstain. `cycle-a.json` and `cycle-b.json` form a two-hop cycle that must
abstain when both selected packs are present.
