# JavaScript `adfa8e0f` residual audit

## Evidence and result

The audited artifact is
`/mnt/optane/tmp/reference-differential/js-top5-adfa8e0f.jsonl` (SHA-256
`870635dab01fdf719cea38e47aed008492145f3f9aed16c42d6ec0dde27f5f41`). All five
records are completed at Bifrost
`adfa8e0f9d915f998f3f91ddbc36ab5ea0ae220f`, are clean at both Bifrost and corpus
heads, and share fingerprint
`4e2100493f415809bff86a802609e65dd80c2520904ebfb5a76516b603512b22`.

Only `nodejs__node` has raw residuals: 39 `missing` classifications. It audited
1,000 files and 10,000 sites with no file errors and no candidate-limit excess.
Its 152 target-truncated sites and sites for 101 skipped targets were classified
`inconclusive`; none of the 39 rows below carries a truncation or limit note. The
other four records have zero `missing` rows (three have a valid zero-file JS
frontier; DevSpace audited 1,609 sites).

Disposition: **one legitimate inverse defect and 38 non-actionable rows**. The
non-actionable rows comprise nine assignment-write/declaration tokens, eleven
reads whose forward result incorrectly points to the same statement's or a later
write, and eighteen receiver/binding false-forward matches. Here, `W`, `T`, and
`F` denote those three categories; `G` is the genuine defect. Lines below are the
one-based source lines stored in the report.

## Exhaustive ledger

| # | Source site | AST/forward evidence and disposition |
|---:|---|---|
| 1 | `deps/acorn/acorn-walk/dist/walk.js:4`, `global.acorn` | **T.** The focused property is the RHS of `global.acorn = global.acorn || {}`. The reported `global.acorn` target is the LHS write, whose value does not exist until after this read. |
| 2 | `deps/acorn/acorn-walk/dist/walk.mjs:210`, `base.BreakStatement` | **W.** Assignment LHS in `base.BreakStatement = base.ContinueStatement = ignore`; the `.js`/`.mjs` target group does not turn this write into a reference. |
| 3 | `deps/acorn/acorn-walk/dist/walk.mjs:237`, `base.TryStatement` | **W.** Assignment LHS of a function-valued member definition. |
| 4 | `deps/acorn/acorn-walk/dist/walk.mjs:276`, `base.VariableDeclarator` | **W.** Assignment LHS of a function-valued member definition. |
| 5 | `deps/acorn/acorn-walk/dist/walk.mjs:365`, `base.UnaryExpression` | **W.** Assignment LHS in a chained member definition. |
| 6 | `deps/acorn/acorn-walk/dist/walk.mjs:381`, `base.CallExpression` | **W.** Assignment LHS in `base.NewExpression = base.CallExpression = ...`. |
| 7 | `deps/npm/lib/commands/doctor.js:142`, `er.message` | **F.** `er` is the local error binding. Forward selected unrelated `read-cmd-shim/lib/index.js::er.message`; receiver identity and file flow do not connect them. |
| 8 | `deps/npm/node_modules/@npmcli/arborist/lib/diff.js:321`, `kid.parent` | **W.** Focus is the property on the LHS of `kid.parent = diff`. |
| 9 | `deps/npm/node_modules/@npmcli/redact/lib/utils.js:69`, `url.searchParams` | **F.** `url` is the destructured callback parameter. Targets in WPT/custom-property tests are unrelated same-spelled receiver fields. |
| 10 | `deps/npm/node_modules/@npmcli/redact/lib/utils.js:77`, `url.username` | **F.** Same callback binding; the two Undici `url.username` targets have no import, alias, or lexical relationship. |
| 11 | `deps/npm/node_modules/@sigstore/protobuf-specs/dist/__generated__/sigstore_common.js:600`, `globalThis.Date` | **F.** This is a builtin-global read; forward selected a mock-timers assignment in another module, not the builtin declaration group. |
| 12 | `deps/npm/node_modules/bin-links/lib/shim-bin.js:4`, `er.code` | **F.** Local error parameter; the four reported npm/arborist/read-cmd-shim fields belong to unrelated `er` bindings. |
| 13 | `deps/npm/node_modules/bin-links/lib/shim-bin.js:28`, `er.code` | **F.** Same local error binding and unrelated cross-file target group as row 12. |
| 14 | `deps/npm/node_modules/iconv-lite/encodings/sbcs-codec.js:23`, `codecOptions.chars` | **W.** Byte 842 focuses the LHS property of `codecOptions.chars = ...`, not the later RHS occurrence. |
| 15 | `deps/npm/node_modules/ini/lib/ini.js:9`, `opt.sort` | **T.** Focus is the RHS in `opt.sort = opt.sort === true`; the reported target is the LHS normalization write, evaluated after the read. |
| 16 | `deps/npm/node_modules/make-fetch-happen/lib/options.js:38`, `options.cache` | **T.** RHS of `options.cache = options.cache || 'default'`; forward points to the same statement's later write. |
| 17 | `deps/npm/node_modules/minipass-fetch/lib/body.js:175`, `er.message` | **F.** Local error binding; unrelated `read-cmd-shim` target. |
| 18 | `deps/npm/node_modules/path-scurry/dist/esm/index.js:713`, `er.code` | **F.** Local error binding; npm/arborist/read-cmd-shim target group is receiver-insensitive. |
| 19 | `deps/npm/node_modules/postcss-selector-parser/dist/parser.js:26`, `descriptor.enumerable` | **T.** RHS of `descriptor.enumerable = descriptor.enumerable || false`; reported same-file target is the not-yet-performed LHS write. |
| 20 | `deps/npm/node_modules/postcss-selector-parser/dist/parser.js:264`, `node.attribute` | **T.** RHS of `node.attribute = (node.attribute || "") + content`; reported target is that statement's later write. |
| 21 | `deps/npm/node_modules/tar/dist/esm/extract.js:29`, `fs.stat` | **F.** `fs` is imported from Node's builtin `fs`; forward selected vendored `graceful-fs/polyfills.js::fs.stat`. |
| 22 | `deps/npm/node_modules/tar/dist/esm/pack.js:110`, `opt.brotli` | **T.** This constructor-option read precedes the later `opt.brotli = {}` write (line 126) selected as `opt.brotli`; it is the caller-provided value, not a use of that write. |
| 23 | `deps/npm/node_modules/tar/dist/esm/write-entry.js:134`, `fs.lstat` | **F.** Builtin `fs` import incorrectly resolves to vendored `graceful-fs`. |
| 24 | `deps/npm/node_modules/tar/dist/esm/write-entry.js:429`, `fs.lstatSync` | **F.** Builtin `fs` import incorrectly resolves to vendored `graceful-fs`. |
| 25 | `deps/npm/node_modules/tinyglobby/dist/index.cjs:304`, `opts.fs.readdirSync` | **T.** The old `opts.fs` value is read while constructing the replacement object in `opts.fs = { readdirSync: opts.fs.readdirSync || ... }`; forward selected the replacement field being initialized. |
| 26 | `deps/undici/src/lib/mock/mock-interceptor.js:76`, `opts.path` | **T.** RHS of `opts.path = serializePathWithQuery(opts.path, opts.query)`; the reported target is the same statement's later LHS write. |
| 27 | `deps/undici/src/lib/web/fetch/index.js:516`, `request.headersList` | **F.** The `request` parameter is unrelated to the two websocket-connection `request.headersList` bindings selected by name. |
| 28 | `deps/undici/src/lib/web/fetch/index.js:1711`, `request.body` | **T.** Focus is the RHS `request.body.source` within `request.body = ...`; forward points to the not-yet-performed LHS write. |
| 29 | `deps/undici/src/lib/web/fetch/index.js:2114`, `fetchParams.controller.controller` (bytes `78788..78798`) | **G.** The same lexical `fetchParams` binding and exact static receiver chain were assigned earlier at line 2045 inside the `ReadableStream.start` closure: `fetchParams.controller.controller = controller`. The later `readableStreamClose(...)` operand is a true read, the forward target is exactly the same-file field group, and the complete inverse result omits it. |
| 30 | `lib/diagnostics_channel.js:79`, `channel._subscribers` | **T.** Forward's `channel._subscribers` group conflates the line-73 initializer in a sibling parameter scope and the line-82 write in this scope. The focused read precedes the only same-scope write, so no reported target is a valid prior definition. |
| 31 | `lib/diagnostics_channel.js:83`, `channel._stores` | **W.** LHS of `channel._stores = undefined`. |
| 32 | `lib/internal/debugger/inspect_probe.js:239`, `result.description` | **F.** Local inspector result; target is `result.result.description` in an unrelated V8 test, with a different receiver chain and no module flow. |
| 33 | `lib/internal/dtls/dtls.js:536`, `options.rejectUnauthorized` | **F.** DTLS function parameter; selected `lib/internal/tls/wrap.js` field is a separate module/binding with no structured connection. |
| 34 | `lib/internal/quic/quic.js:1923`, `inner.direction` | **F.** Source is `this.#inner.direction` in a getter. Forward reports plain-local alias target `inner.direction` from constructor scope instead of the `QuicStream.#inner` object member; it crosses method/receiver identity without proof. |
| 35 | `lib/internal/quic/quic.js:3018`, `inner.onversionnegotiation` | **F.** Source is `this.#inner.onversionnegotiation`; target `inner.onversionnegotiation` comes from setter/cleanup local aliases rather than the private-object member declaration. |
| 36 | `lib/internal/quic/quic.js:4002`, `inner.pendingOpen.reject` | **W.** Property is the LHS of `inner.pendingOpen.reject = undefined`. |
| 37 | `lib/internal/quic/quic.js:4141`, `inner.state` | **F.** Source is `endpoint.#inner.state`, while `inner.state` collapses plain-local assignments from multiple QUIC classes/scopes. The target group is not the endpoint private-object member. |
| 38 | `lib/internal/quic/quic.js:4322`, `inner.busy` | **T.** Getter reads `this.#inner.busy`; reported `inner.busy` declarations are later local-alias writes in the setter/cleanup paths, not the earlier `#inner` object-literal key. |
| 39 | `tools/eslint-rules/no-keyobject-cryptokey-instanceof.js:68`, `property.value` | **F.** Local ESLint AST-property binding; targets in V8 fuzzer/detect-builtins tools are unrelated same-spelled receivers. |

Rows 2-6 and 20 also appeared in the `127c5817` baseline and retain the same
non-actionable dispositions. The other 17 baseline residuals are absent after the
JavaScript fixes; the final sample exposes 33 new rows, of which only row 29 is
legitimate.

An independent exact ephemeral probe reproduced row 29 as `missing` with one
queried target and no limits or file errors. Its artifact is
`/mnt/optane/tmp/reference-differential/js-exact-node-fetch-controller-adfa8e0f-audit.jsonl`
(SHA-256
`ec151a012cbc23b0dba0957a24dd2c761b5de80e81b81d2a1dc8efccde206ed1`). It is
diagnostic rather than acceptance evidence because concurrent documentation work
made its top-level `bifrost_dirty` true; the clean full-corpus record above is the
authoritative witness.

## Narrow fix recommendation

Extend `JsTsDirectPropertyDefinition` from an identifier-only receiver to a
tree-sitter-derived static member receiver chain with an identifier root. Store
and compare the member segments structurally while continuing to key lexical
scope only by the root binding. This admits the prior exact chain
`fetchParams.controller.controller = ...` for the later identical read without
opening receiver-insensitive matching.

Behavior coverage should prove the nested positive through the public targeted
usage surface and reject `other.controller.controller`,
`fetchParams.other.controller`, sibling-function and shadowed roots, reads before
the definition, and write occurrences. The implementation must consume AST
fields/nodes directly; it must not split or scan receiver source text.
