# Python standard-library semantic packs

This directory pins the source inputs used to build Bifrost's published Python
standard-library declaration pack. Generated manifests and shards are release
assets; they are not checked into Git.

The pinned-spec schema is ecosystem neutral and is documented in
`semantic-packs/jvm/README.md`. This directory adds the first `python_stub`
specification: an exact source set of `.pyi` files taken from one pinned
typeshed revision.

## The pinned slice

`typeshed-stdlib-2026.8.8.json` pins typeshed revision
`1620e225476597f34177351ef913dc8390dade30` and lists 15 stub files. The
slice is deliberately bounded to the modules an ordinary Python program
touches first:

| Module | Pinned stub files |
| --- | --- |
| `builtins` | `builtins.pyi` |
| `typing` | `typing.pyi` |
| `re` | `re.pyi` |
| `os` | `os/__init__.pyi` |
| `os.path` | `os/path.pyi`, `posixpath.pyi`, `ntpath.pyi` |
| `json` | `json/__init__.pyi`, `json/decoder.pyi`, `json/encoder.pyi`, `json/scanner.pyi`, `json/tool.pyi` |
| `collections` | `collections/__init__.pyi` |
| `collections.abc` | `collections/abc.pyi`, `_collections_abc.pyi` |

The pack is one slice of the standard library, not the standard library. It
publishes nothing about `sys`, `pathlib`, `subprocess`, or the other ~270
stdlib modules typeshed carries. A consumer must not read a name's absence
from this pack as a statement about the standard library. The manifest
records `completeness: complete` because that field states extraction
fidelity for the artifact the pack names, and the Python boundary judge reads
it per module: a module this pack does not publish never reaches an absence
verdict.

`os.path` and `collections.abc` are re-export shims in typeshed. Their stubs
spell `from posixpath import *` and `from _collections_abc import *`, and the
producer records a wildcard re-export as the `*` binding rather than
enumerating it. Both modules therefore publish the honest statement "this
surface binds names the pack could not enumerate", and the Python boundary
judge reports them as incomplete instead of proving a name absent. The
modules the shims re-export from are pinned as well, so the declarations
themselves are in the pack under their own module names: `posixpath.join`
exists, `os.path.join` does not.

Typeshed supports Python 3.10 through 3.14, so the pack's compatibility and
activation name the `cpython` toolchain over that range. Typeshed guards
version-specific and platform-specific declarations with `sys.version_info`
and `sys.platform` blocks.

The producer keeps a pack static and still never evaluates a guard. It records
the guard on the declaration instead: an inclusive minimum toolchain version,
an exclusive maximum, and the activation targets the block requires or
excludes. Activation pins one exact interpreter version and one target, and it
drops a declaration only when a recorded constraint *provably* excludes that
interpreter. Under a cpython 3.13.5 Linux activation the pack therefore stops
resolving `builtins.float.from_number` (`sys.version_info >= (3, 14)`) and
`os.startfile` (`sys.platform == "win32"`), while every unguarded name resolves
as before.

The honesty rule runs one way only. A guard this producer cannot express, and
a coordinate the activation does not pin, both keep the declaration and mark it
as read incompletely rather than dropping it. Two branches that declare one
identity leave no branch's condition necessary, so that declaration stays
active for every activation as well.

Read a published name as "this interpreter declares this name, or its guard
could not be read". A name this slice covers and this activation dropped is one
the pinned interpreter provably does not declare. A name the slice never
covered is still outside the pack's statements, as the module table above
says.

An activation supplies its target as the interpreter's own `sys.platform`
value, which is the vocabulary typeshed's platform guards name. A target from
another vocabulary would read as an ordinary mismatch and could drop a
declaration the interpreter has.

## License

Typeshed is licensed under the Apache License, Version 2.0. The pinned
revision and the license are recorded in the specification's provenance and
in `notices/typeshed-stdlib-2026.8.8.txt`, which ships with the pack.

## Regeneration

`scripts/build-pinned-python-semantic-packs.sh OUTPUT_DIR WORK_DIR` downloads
the pinned archive, checks its SHA-256, extracts the stub root under the
pinned directory name, and then generates and verifies the bundle. The
pinned artifact is a source set rather than one file, so its digest is the
canonical digest over the listed stub paths and bytes. Generation verifies
that digest itself and refuses a tree that differs.

GitHub builds a source archive on demand. The archive digest that the script
checks is therefore a weaker pin than the artifact digest that `generate`
enforces: a change in GitHub's archive encoding would fail the script's
checksum without any change to the pack the specification names. Repin the
archive digest in that case; the pack digest and the pinned revision stay the
same.

To run the same steps by hand:

```console
cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  /path/to/output \
  semantic-packs/python/typeshed-stdlib-2026.8.8.json /path/to/typeshed-stdlib-1620e2254765

cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  /path/to/output
```
