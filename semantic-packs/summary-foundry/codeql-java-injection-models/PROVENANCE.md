# CodeQL Java injection endpoint slice (#1871 milestone 4.6)

These `*.model.yml` files are a reduced, verbatim slice of the CodeQL
Models-as-Data Java corpus. The demand sweep translates their `sourceModel` and
`sinkModel` rows into taint endpoints and builds the `require-model` Java taint
policy from them.

- Upstream: <https://github.com/github/codeql>
- Revision: `c9142680f5b6409dbe0944350321c54e8c801e61`
  (the same pin as `semantic-packs/summary-corpora/pins.json`)
- Upstream paths: `java/ql/lib/ext/{javax.servlet.http,java.sql,java.lang}.model.yml`
- License: MIT (see `LICENSE` in the upstream repository)

Every row below is copied verbatim from the pinned upstream files. The slice is
reduced, not rewritten: it keeps the `sourceModel` and `sinkModel` rows for the
canonical injection APIs whose method names are distinctive, and drops rows and
extensions the sweep does not use. The reduction is deliberate: the RQL `call`
selector can constrain only the callee's spelled name, not the receiver type, so
a selector for a generic accessor name (`getName`, `getValue`) would match every
call of that name regardless of receiver. Keeping distinctive injection-API
names (`getParameter`, `executeQuery`, `exec`) keeps the name-based selectors
meaningful. This reduction is recorded here so the slice is reproducible against
the pin.
