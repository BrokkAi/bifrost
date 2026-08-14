# Examples

A worked example for the Python package published from this repo,
`brokk-bifrost-searchtools` (imported as `bifrost_searchtools`), plus a script
to validate that the **published wheel** actually works.

## Files

- **`searchtools_demo.py`** — a minimal app that drives the public
  `SearchToolsClient` API (`search_symbols`, `get_summaries`, `list_symbols`,
  `get_symbol_sources`) against a codebase and prints the results. It carries
  [PEP 723](https://peps.python.org/pep-0723/) inline dependencies, so
  `uv run` fetches the published wheel from PyPI automatically — no manual
  install.
- **`validate_published_wheel.sh`** — installs the published wheel from PyPI into
  a clean, throwaway venv and runs the demo against a generated sample project.
  This is what proves the publish actually worked.

## Validate the published wheel (the thing you actually want)

```sh
examples/validate_published_wheel.sh
```

What it does, and why each step matters:

1. Reads the version from `pyproject.toml` (so it validates the version you just
   published) and targets `brokk-bifrost-searchtools==<that version>`.
2. Generates a tiny sample Python project in a temp dir.
3. Creates a clean venv and installs the wheel with `--only-binary=:all:`, so it
   **fails loudly if no wheel matches this platform** instead of silently
   compiling the sdist.
4. Asserts `bifrost_searchtools.__file__` lives in the venv's `site-packages`
   and not in this checkout — otherwise you'd be testing local source, not the
   wheel — and that the native extension (`_native.*.so` / `.pyd`) is present.
5. Runs `searchtools_demo.py` against the sample project.

Prints `PASS: …` on success. By default it pins **Python 3.12** (the wheels are
`cp312-abi3`); override with `BIFROST_VALIDATE_PYTHON=3.13 …`. `uv` is used if
present (and will fetch a managed CPython if needed); otherwise it falls back to
`python3 -m venv`, which needs Python ≥ 3.12 on `PATH`.

> Heads up: running `searchtools_demo.py` directly from this checkout imports the
> **local** source tree and locally built `.so`, not the PyPI wheel — useful for
> hacking on the API, but it does not validate publishing. Only the script above
> does.

## Run the demo against any repo

The demo declares its dependency inline (PEP 723), so `uv run` pulls the
published wheel into an isolated environment for you — even from inside this
checkout, this exercises the *published* wheel, not the local source:

```sh
uv run examples/searchtools_demo.py --root /path/to/repo Calculator compute
# or, for a directory overview, omit the patterns:
uv run examples/searchtools_demo.py --root /path/to/repo
```

The script is also executable directly (`examples/searchtools_demo.py …`) via its
`#!/usr/bin/env -S uv run --script` shebang. Running it with a plain `python` from
this checkout works too, but then it imports the *local* source tree, not the wheel.

## "Did I break the publish?" checklist

- All platform wheels present on PyPI for this version
  (`https://pypi.org/pypi/brokk-bifrost-searchtools/json`): macOS x86_64 + arm64,
  manylinux x86_64 + aarch64, Windows amd64, plus the sdist.
- `validate_published_wheel.sh` prints `PASS` on your machine.
- Tag `v<version>` matches `Cargo.toml` (the single source of truth; the wheel
  inherits it via maturin's dynamic version, and the workflow's `verify-version`
  job enforces tag == `Cargo.toml`).
- Re-running the publish workflow for an already-published version is **expected
  to fail** at the upload step — PyPI refuses to overwrite existing files. Bump
  the version to publish again.
