# Python process-input and os.system packs

Three reviewed packs carry the first Python security contract:

- `process-inputs/bifrost.python-process-inputs.json` publishes the `os`
  module's `environ` container and the `sys` module's `argv` container as
  runtime process inputs, with one keyed-read behavior each.
- `os-command/bifrost.python-os-command-declarations.json` declares the `os`
  module type and the exact `os.system(command)` member.
- `os-command/bifrost.python-os-command-summaries.json` carries that member's
  complete procedure summary: no transfer, and one escape effect on the
  command argument.

The shipped `bifrost.security.python.process-input-to-os-system` policy joins
them: a keyed read of either container that reaches the command argument of the
exact `os.system` member.

## Why these packs are not review-gated

The reviewed Node runtime-values packs pin one distribution, so a workspace has
to name that revision and then name the pack before the model applies. These
packs are a different kind of claim, and they carry the Go standard-library
packs' contract instead: the Python standard-library reference specifies
`os.environ` as the process environment, `sys.argv` as the launch arguments,
and `os.system(command)` as a subshell execution, for every conforming
implementation on every platform. Nothing in that claim varies with an
interpreter build, so the runtime record names no distribution artifact and no
platform, architecture, or module mode, and the activation selector carries no
artifact evidence for one to bind.

A workspace states the profile by containing Python: `python_process_input_evidence`
mints one evidence row per present Python language, carrying the reviewed
profile configuration and nothing else. The engine refuses any runtime record
whose declared scope it does not implement, so a record that did name a
platform would stay incomplete rather than silently publishing.

## Digest recipes

- The runtime profile digest is the SHA-256 of the RFC 8785 canonical JSON of
  the exposure's authored `runtime` applicability record:
  `b95b6625659ac476f274bdb3a305f20f497727137dc85aa96e50a989d57d8afd`. The
  acceptance test recomputes it from the checked-in pack with the production
  canonicalizer, so the recipe is pinned rather than documented.
- The exposure and behavior evidence digests are the SHA-256 of the reviewed
  CPython documentation at the `v3.13.5` tag:
  `Doc/library/os.rst` is
  `709ea0fac5c4283df534aa0d46b97908d65ee5ffe96fddf6bd187784170359d6` and
  `Doc/library/sys.rst` is
  `5f94a3e3937d1b0ead710ecce7a8d0415df95187b64065f1f7452074e7333301`. Those
  documents state that `os.environ` is a mapping of the process environment
  captured when the module is first imported, that changes made after that time
  are not reflected in it except through `os.environ` itself, that `sys.argv`
  is the list of command-line arguments, and that `os.system` executes its
  string argument in a subshell. Those statements ground the eager,
  value-semantics, pristine-input-until-write, and escape claims.

## Coverage boundary

`os.environ[key]` raises `KeyError` and `sys.argv[index]` raises `IndexError`,
so both behaviors declare `may-throw`. The reviewed claim is about the value a
read produces on its normal path, which a read that abandons control never
produces; the load's exceptional control flow stays the frontend's own lowered
abort edge, and the model discharges no claim about it.

The keyed-read proof is refused, and the result stays typed incomplete rather
than clean, when any of these holds: the root name is bound by anything other
than imports of the named module, an enclosing function rebinds it, the key is
not a plain string or integer literal, the module writes the container or lets
the container or the module object escape, another workspace Python module
writes the container, or anything that can run before the read in the read's
own execution context is a call.

`os.environ` folds keys to upper case on Windows. Every key of the container is
process-environment input either way, so the source claim is unaffected; a
policy that names one exact key would still miss a differently cased spelling
on that platform.

The `os.system` dispatch closure additionally requires that no workspace Python
file writes `os.system`, lets the `os` module object escape to an unseen
writer, or reads `sys.modules`. Reflection through other module tables is
outside the proof.

Compile the packs with:

```sh
cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- compile \
  semantic-packs/python/process-inputs/bifrost.python-process-inputs.json \
  crates/bifrost-semantic-packs/embedded/python-process-inputs
```
