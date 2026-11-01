#!/usr/bin/env python3
"""Rewrite a maturin-built Bifrost wheel to carry its native file xz-compressed.

Both PyPI wheels hold a file of about 300 MB that deflates to 85-98 MB,
against PyPI's 100 MiB per-file limit (#8288): the brokk-bifrost CLI wheel's
`bifrost` binary, and the brokk-bifrost-searchtools wheel's extension module
`bifrost_searchtools/_native.abi3.so` (`_native.pyd` on Windows). xz at
preset 9e brings either to about 55 MB; zstd was larger and is in the standard
library only from Python 3.14.

The rewrite keeps maturin's platform tags, metadata, licence files and SBOM.
It replaces the native file with the file xz-compressed, a `payload.json`
record of the file's name, SHA-256 and size, and `_xz_payload.py`
(packaging/xz-payload), which unpacks it on first use. RECORD is regenerated.
The kind of wheel decides the rest:

- CLI: maturin's `bindings = "bin"` wheel holds the binary in
  `<name>.data/scripts/`. The binary and the old sh/cmd wrapper scripts are
  dropped, and the `brokk_bifrost_cli` launcher package
  (packaging/bifrost-cli/launcher) and `bifrost` / `brokk-bifrost`
  console-script entry points are added. Installers turn those entry points
  into native launchers on every platform, including Windows `.exe` wrappers.
- searchtools: the payload goes beside the extension module it replaces, in
  `bifrost_searchtools/`, whose client loads it through
  `importlib.machinery.ExtensionFileLoader` after unpacking.

The rewritten wheel goes to OUTPUT_DIRECTORY under its original name. The
input wheel is read in full first, so OUTPUT_DIRECTORY may be the input's own
directory. It must not be for the CLI wheel on Linux: maturin-action builds in
a manylinux container as root and then chowns its `--out` directory back to
the runner, but resolves that path against the workspace root rather than its
`working-directory`, so `packaging/bifrost-cli/dist` stays owned by root and
the runner user cannot write there. The searchtools wheel builds at the
workspace root, whose `dist` the chown reaches.

Usage: compress-python-wheel.py OUTPUT_DIRECTORY WHEEL...
"""

import base64
import hashlib
import json
import lzma
import os
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNPACKER = ROOT / "packaging/xz-payload/_xz_payload.py"
CLI_LAUNCHER = ROOT / "packaging/bifrost-cli/launcher/brokk_bifrost_cli/__init__.py"
CLI_PACKAGE = "brokk_bifrost_cli"
CLI_BINARIES = ("bifrost", "bifrost.exe")
CLI_WRAPPERS = ("brokk-bifrost", "brokk-bifrost.cmd")
CLI_ENTRY_POINTS = (
    "[console_scripts]\n"
    f"bifrost = {CLI_PACKAGE}:main\n"
    f"brokk-bifrost = {CLI_PACKAGE}:main\n"
)
SEARCHTOOLS_PACKAGE = "bifrost_searchtools"
SEARCHTOOLS_MODULES = ("_native.abi3.so", "_native.pyd")


def record_hash(data):
    """Return a RECORD hash field: urlsafe base64 SHA-256 without padding."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"sha256={digest}"


def plan_rewrite(wheel, names, dist_info):
    """Return the wheel's native file, its package, its compressed name, the members to drop, and the files to add."""
    data_scripts = dist_info.replace(".dist-info", ".data") + "/scripts/"
    binaries = [data_scripts + name for name in CLI_BINARIES if data_scripts + name in names]
    modules = [f"{SEARCHTOOLS_PACKAGE}/{name}" for name in SEARCHTOOLS_MODULES
               if f"{SEARCHTOOLS_PACKAGE}/{name}" in names]
    assert len(binaries) + len(modules) == 1, (
        f"{wheel} must hold exactly one of {CLI_BINARIES} in {data_scripts} "
        f"or {SEARCHTOOLS_MODULES} in {SEARCHTOOLS_PACKAGE}/: {names}"
    )
    if binaries:
        assert not any(name.startswith(f"{CLI_PACKAGE}/") for name in names), f"{wheel} is already compressed"
        dropped = {data_scripts + name for name in CLI_WRAPPERS}
        added = [
            (f"{CLI_PACKAGE}/__init__.py", CLI_LAUNCHER.read_bytes()),
            (f"{dist_info}/entry_points.txt", CLI_ENTRY_POINTS.encode()),
        ]
        return binaries[0], CLI_PACKAGE, "bifrost.xz", dropped, added
    assert f"{SEARCHTOOLS_PACKAGE}/payload.json" not in names, f"{wheel} is already compressed"
    file = modules[0].rsplit("/", 1)[1]
    return modules[0], SEARCHTOOLS_PACKAGE, f"{file}.xz", set(), []


def compress_wheel(wheel, output_directory):
    """Write a copy of one maturin wheel, carrying its native file xz-compressed, to output_directory."""
    with zipfile.ZipFile(wheel) as source:
        names = source.namelist()
        dist_info = next(name.split("/")[0] for name in names if name.endswith(".dist-info/WHEEL"))
        native, package, compressed_name, dropped, added = plan_rewrite(wheel, names, dist_info)
        file = native.rsplit("/", 1)[1]
        data = source.read(native)
        date_time = source.getinfo(native).date_time
        dropped |= {native, f"{dist_info}/RECORD"}
        kept = [(source.getinfo(name), source.read(name)) for name in names if name not in dropped]

    payload = json.dumps(
        {"file": file, "compressed": compressed_name,
         "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)},
        indent=2,
    ).encode() + b"\n"
    compressed = lzma.compress(data, preset=9 | lzma.PRESET_EXTREME)
    added = [
        *((name, content, zipfile.ZIP_DEFLATED) for name, content in added),
        (f"{package}/_xz_payload.py", UNPACKER.read_bytes(), zipfile.ZIP_DEFLATED),
        (f"{package}/payload.json", payload, zipfile.ZIP_DEFLATED),
        # Already compressed: deflating it again only costs time.
        (f"{package}/{compressed_name}", compressed, zipfile.ZIP_STORED),
    ]

    output = output_directory / wheel.name
    records = []
    descriptor, temporary = tempfile.mkstemp(prefix=".compress-", suffix=".whl", dir=output_directory)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w") as target:
            def write(name, content, method):
                info = zipfile.ZipInfo(name, date_time)
                info.compress_type = method
                info.external_attr = 0o100644 << 16
                target.writestr(info, content, compresslevel=9 if method == zipfile.ZIP_DEFLATED else None)
                records.append(f"{name},{record_hash(content)},{len(content)}")

            for name, content, method in added:
                write(name, content, method)
            for info, content in kept:
                target.writestr(info, content)
                records.append(f"{info.filename},{record_hash(content)},{len(content)}")
            records.append(f"{dist_info}/RECORD,,")
            write_record = zipfile.ZipInfo(f"{dist_info}/RECORD", date_time)
            write_record.compress_type = zipfile.ZIP_DEFLATED
            write_record.external_attr = 0o100644 << 16
            target.writestr(write_record, "\n".join(records) + "\n")
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    print(json.dumps({
        "wheel": str(output),
        "file": native,
        "file_bytes": len(data),
        "compressed_bytes": len(compressed),
        "wheel_bytes": output.stat().st_size,
    }))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    output_directory = Path(sys.argv[1])
    output_directory.mkdir(parents=True, exist_ok=True)
    for argument in sys.argv[2:]:
        compress_wheel(Path(argument), output_directory)
