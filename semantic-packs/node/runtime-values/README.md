# Node runtime-values packs

`typescript/bifrost.node-runtime-values.json` and
`javascript/bifrost.node-runtime-values.json` carry the reviewed Node
runtime-values contract for the `keyed_read_value` capability. Each pack
publishes one enabled `process` global exposure for the Node v22.11.0
linux/x64 main-realm CommonJS profile, plus two keyed-read behaviors:
static-property reads of `process.env` and static-index reads of
`process.argv`. TSX workspaces use the TypeScript pack; the shared
TypeScript front end parses both dialects and the acceptance test proves
TSX positives and near misses independently.

## Layered contract

An exposure marked `enabled` is intrinsically eligible within its model;
it does not bypass pack activation. Every pack in this directory sets
`safety.review_required`, so the exposure stays inert until the host
supplies exact activation evidence (language, npm ecosystem, Node
artifact coordinates, profile configuration, and artifact digest) and an
explicit compatible `enable` control names the pack id. The activation
report retains that enable decision; the published endpoint rows retain
the exposure, behavior, and active-model-set identities.

The packs carry no authored binding evidence or observations. Only
workspace-derived analyzer evidence can authoritatively describe lexical
bindings, rebinding exclusions, keyed loads, mutation state, and
observation identity in a particular workspace, so the production
evaluator joins the authored exposure and behavior records with the
workspace's own syntax and executable-semantic facts. Parameters, locals,
and imports that lexically bind `process` are conclusively excluded;
reassignment, dynamic keys and indices, unsupported runtimes and
profiles, and incomplete analysis stay typed incomplete.

## Digest recipes

All digests are SHA-256 over exact reviewed bytes. Nothing here uses a
placeholder.

- The runtime artifact digest is the SHA-256 of the official
  `node-v22.11.0.tar.gz` source distribution archive as listed in the
  distributor checksum file at
  `https://nodejs.org/dist/v22.11.0/SHASUMS256.txt`:
  `24e5130fa7bc1eaab218a0c9cb05e03168fa381bb9e3babddc6a11f655799222`.
  The digest pins the exact Node revision; the profile statement below
  selects the modeled execution environment.
- The behavior evidence digest is the SHA-256 of the reviewed
  `doc/api/process.md` document at the `v22.11.0` tag, byte-identical
  inside the archive and at
  `https://github.com/nodejs/node/blob/v22.11.0/doc/api/process.md`:
  `978ccf50488c3378fb7dc8e89945f3db4e613627af6a8ed63c6da367a04e478a`.
  The reviewed sections state that `process.argv` is the materialized
  launch-argument array, that `process.env` is the user-environment
  object, that reads yield a value or `undefined`, and that both
  containers are writable, which grounds the nonthrowing, eager,
  value-or-undefined, and pristine-input-until-write claims.
- The runtime profile digest is the SHA-256 of the RFC 8785 canonical
  JSON of the exposure's authored `runtime` applicability record:
  `70db7f8c799decb554bc25e8bf410079c8b377f2852ee2a982d56db40f054056`.
  The acceptance test recomputes this digest from the checked-in pack
  with the production canonicalizer, so the recipe is pinned, not just
  documented.

## Coverage boundary

The profile models the main realm of one Node process launched without
preload customization on Linux x64 in CommonJS mode. Worker threads,
which receive a copy of the parent environment, other platforms and
architectures, other module modes, and other `process` members are
outside the reviewed contract and stay incomplete. The mutation proof
closes a single-file module for direct writes to the `process` root;
unknown external calls outside the read's own function and unmodeled
module-load effects are outside the closed proof and are excluded by the
`closed-workspace-no-preloads` host assumption the profile carries. A
workspace whose module loading writes `process.env` or `process.argv`
(such as one that populates the environment from a dotenv file) does not
satisfy that assumption and must not select this profile.

Configuration documents cannot activate or intersect this domain: pack
selection requires exact code-runtime evidence rows, and the evaluator
only joins loads from JavaScript/TypeScript executable artifacts.

The complete upstream notice is retained in
`notices/node-v22.11.0.txt`.

Compile the packs with:

```sh
cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- compile \
  semantic-packs/node/runtime-values/typescript/bifrost.node-runtime-values.json \
  crates/bifrost-semantic-packs/embedded/node-runtime-values-typescript
```
