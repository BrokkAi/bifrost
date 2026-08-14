#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "brokk-bifrost-searchtools",
# ]
# ///
"""Minimal example app for the published ``brokk-bifrost-searchtools`` wheel.

It drives the public :class:`SearchToolsClient` API against a codebase and
prints the results, so you can confirm by eye that the native pyo3 extension
loads and actually answers queries.

The PEP 723 metadata block above lets ``uv`` run this with the published wheel
fetched from PyPI into an isolated environment -- no manual install needed::

    uv run examples/searchtools_demo.py --root /path/to/repo Calculator compute

Because ``uv run`` resolves the dependency from PyPI (and the script's own
directory, not the repo root, is what lands on ``sys.path``), this exercises the
*published* wheel even when run from inside this checkout. If you instead invoke
it with a plain ``python`` from this checkout, ``import bifrost_searchtools``
resolves to the local source tree and the locally built ``.so``. For a strict,
version-pinned check (forced binary wheel + origin assertions), use
``validate_published_wheel.sh``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Keep the background semantic indexer (and its model download) out of a plain
# "does it work" run. Export BIFROST_SEMANTIC_INDEX=on yourself to opt back in.
os.environ.setdefault("BIFROST_SEMANTIC_INDEX", "off")

from bifrost_searchtools import SearchToolsClient


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def print_origin() -> None:
    """Show where the package and its native extension were imported from.

    This is the single most useful line when validating a wheel: it tells you
    whether you are exercising the installed wheel or a local checkout.
    """
    import bifrost_searchtools
    from bifrost_searchtools import _native

    section("Loaded from")
    print(f"  bifrost_searchtools : {bifrost_searchtools.__file__}")
    print(f"  native extension    : {_native.__file__}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Codebase to analyze (default: current directory).",
    )
    parser.add_argument(
        "patterns",
        nargs="*",
        help="Symbol name patterns to search for. Omit to print a directory overview instead.",
    )
    args = parser.parse_args(argv)

    print_origin()

    root = args.root.expanduser().resolve()
    if not root.exists():
        print(f"error: --root does not exist: {root}", file=sys.stderr)
        return 2

    section(f"Opening session on {root}")
    # The client starts the native session lazily; the context manager closes it.
    with SearchToolsClient(root=root) as client:
        if not args.patterns:
            # No patterns: a "." target asks for a compact inventory of the tree,
            # which works as a sanity check on any repo.
            section("Directory overview  (get_summaries['.'])")
            print(client.get_summaries(["."]).render_text())
            return 0

        section(f"search_symbols({args.patterns})")
        symbols = client.search_symbols(args.patterns)
        print(symbols.render_text())

        if not symbols.files:
            print("\n(no symbols matched -- nothing further to drill into)")
            return 0

        # Drill into the first file and first function we found, so the demo
        # exercises summaries, skim listing, and source extraction too.
        first_file = symbols.files[0]
        section(f"get_summaries(['{first_file.path}'])")
        print(client.get_summaries([first_file.path]).render_text())

        section(f"list_symbols(['{first_file.path}'])")
        print(client.list_symbols([first_file.path]).render_text())

        functions = first_file.functions
        if functions:
            target = functions[0].symbol
            section(f"get_symbol_sources(['{target}'])")
            print(client.get_symbol_sources([target]).render_text())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
