#!/usr/bin/env python3
"""Rewrite a maturin-built brokk-bifrost CLI wheel to carry its binary xz-compressed.

maturin's `bindings = "bin"` wheel holds the raw `bifrost` binary in
`<name>.data/scripts/`. It is about 300 MB and deflates to about 95 MB, against
PyPI's 100 MiB per-file limit (#8288). xz at preset 9e brings it to about
55 MB; zstd was larger and is in the standard library only from Python 3.14.

The rewrite keeps maturin's platform tags, metadata, licence files and SBOM,
and replaces the binary and the old sh/cmd wrapper scripts with the
`brokk_bifrost_cli` launcher package (packaging/bifrost-cli/launcher), the
compressed binary, a payload record of the binary's SHA-256, size and name,
and `bifrost` / `brokk-bifrost` console-script entry points. Installers turn
those entry points into native launchers on every platform, including
Windows `.exe` wrappers. RECORD is regenerated.

The rewritten wheel goes to OUTPUT_DIRECTORY under its original name, and the
input wheel is left as it is. On Linux, maturin-action builds in a manylinux
container as root and then chowns its `--out` directory back to the runner,
but resolves that path against the workspace root rather than its
`working-directory`, so `packaging/bifrost-cli/dist` stays owned by root and
the runner user cannot write there.

Usage: compress-cli-wheel.py OUTPUT_DIRECTORY WHEEL...
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

LAUNCHER = Path(__file__).resolve().parents[2] / "packaging/bifrost-cli/launcher/brokk_bifrost_cli/__init__.py"
PACKAGE = "brokk_bifrost_cli"
BINARIES = ("bifrost", "bifrost.exe")
WRAPPERS = ("brokk-bifrost", "brokk-bifrost.cmd")
ENTRY_POINTS = (
    "[console_scripts]\n"
    f"bifrost = {PACKAGE}:main\n"
    f"brokk-bifrost = {PACKAGE}:main\n"
)


def record_hash(data):
    """Return a RECORD hash field: urlsafe base64 SHA-256 without padding."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"sha256={digest}"


def compress_wheel(wheel, output_directory):
    """Write a copy of one maturin CLI wheel, carrying its binary xz-compressed, to output_directory."""
    with zipfile.ZipFile(wheel) as source:
        names = source.namelist()
        dist_info = next(name.split("/")[0] for name in names if name.endswith(".dist-info/WHEEL"))
        data_scripts = dist_info.replace(".dist-info", ".data") + "/scripts/"
        binaries = [data_scripts + name for name in BINARIES if data_scripts + name in names]
        assert len(binaries) == 1, f"{wheel} must hold exactly one of {BINARIES} in {data_scripts}: {names}"
        assert not any(name.startswith(f"{PACKAGE}/") for name in names), f"{wheel} is already compressed"
        executable = binaries[0].rsplit("/", 1)[1]
        binary = source.read(binaries[0])
        date_time = source.getinfo(binaries[0]).date_time
        dropped = {binaries[0], f"{dist_info}/RECORD", *(data_scripts + name for name in WRAPPERS)}
        kept = [(source.getinfo(name), source.read(name)) for name in names if name not in dropped]

    payload = json.dumps(
        {"executable": executable, "sha256": hashlib.sha256(binary).hexdigest(), "size": len(binary)},
        indent=2,
    ).encode() + b"\n"
    compressed = lzma.compress(binary, preset=9 | lzma.PRESET_EXTREME)
    added = [
        (f"{PACKAGE}/__init__.py", LAUNCHER.read_bytes(), zipfile.ZIP_DEFLATED),
        (f"{PACKAGE}/payload.json", payload, zipfile.ZIP_DEFLATED),
        # Already compressed: deflating it again only costs time.
        (f"{PACKAGE}/bifrost.xz", compressed, zipfile.ZIP_STORED),
        (f"{dist_info}/entry_points.txt", ENTRY_POINTS.encode(), zipfile.ZIP_DEFLATED),
    ]

    output = output_directory / wheel.name
    records = []
    descriptor, temporary = tempfile.mkstemp(prefix=".compress-", suffix=".whl", dir=output_directory)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w") as target:
            def write(name, data, method):
                info = zipfile.ZipInfo(name, date_time)
                info.compress_type = method
                info.external_attr = 0o100644 << 16
                target.writestr(info, data, compresslevel=9 if method == zipfile.ZIP_DEFLATED else None)
                records.append(f"{name},{record_hash(data)},{len(data)}")

            for name, data, method in added:
                write(name, data, method)
            for info, data in kept:
                target.writestr(info, data)
                records.append(f"{info.filename},{record_hash(data)},{len(data)}")
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
        "executable": executable,
        "binary_bytes": len(binary),
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
