"""Run the bifrost binary that the brokk-bifrost wheel ships xz-compressed.

The binary is about 300 MB and PyPI caps a file at 100 MiB, so the wheel
carries ``bifrost.xz`` and ``payload.json`` (the binary's SHA-256, size and
file name, recorded when the wheel was built) instead of the binary. The
``bifrost`` and ``brokk-bifrost`` console scripts call ``main``, which unpacks
the binary once and then replaces this process with it.

Where the binary goes: ``bin-<digest>/`` beside this file, so the copy lives
and is upgraded with the installation, or, when site-packages is read-only (a
system or image install), the per-user cache directory. The digest in the
directory name makes a wheel with a different binary unpack its own copy, and
keeps the executable's own name ``bifrost`` for its usage text. ``pip
uninstall`` does not know about the unpacked copy and leaves ``bin-<digest>/``
behind; a later unpack in this directory removes copies of other digests.
Copies in the shared cache are never removed, because another installation may
be about to run them.

Only a verified copy ever reaches its final path: the binary is decompressed
into a temporary file in the same directory, hashed while it is written,
fsynced and renamed into place. Concurrent first runs each unpack their own
temporary file and the renames are atomic, so every run sees either no binary
or a complete one. A later run therefore checks the size alone.

This module uses only the standard library, for every Python the wheel
supports (3.8 and later).
"""

import errno
import hashlib
import json
import lzma
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent
_CHUNK = 1 << 20
# A directory we cannot write to: try the next location.
_UNWRITABLE = (errno.EACCES, errno.EPERM, errno.EROFS)


def main():
    """Run the unpacked binary with this process's arguments, as the console scripts do."""
    executable = unpacked_executable()
    arguments = [str(executable), *sys.argv[1:]]
    if os.name != "nt":
        # The binary replaces this process: it keeps the pid, receives every
        # signal directly and exits with its own status.
        os.execv(str(executable), arguments)
    # Windows has no exec. The console delivers Ctrl+C and Ctrl+Break to the
    # child as well, so this process ignores them, waits, and returns the
    # child's exit code.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGBREAK, signal.SIG_IGN)
    sys.exit(subprocess.call(arguments))


def unpacked_executable():
    """Return the verified, unpacked binary, unpacking it on first use."""
    payload = json.loads((_PACKAGE / "payload.json").read_text(encoding="utf-8"))
    directory_name = f"bin-{payload['sha256'][:16]}"
    try:
        return _unpack_into(_PACKAGE, directory_name, payload)
    except OSError as error:
        if error.errno not in _UNWRITABLE:
            raise
    return _unpack_into(_cache_directory(), directory_name, payload)


def _unpack_into(parent, directory_name, payload):
    directory = parent / directory_name
    target = directory / payload["executable"]
    if _is_unpacked(target, payload):
        return target
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{payload['executable']}.", dir=directory)
    try:
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as output, lzma.open(_PACKAGE / "bifrost.xz") as source:
            chunk = source.read(_CHUNK)
            while chunk:
                digest.update(chunk)
                output.write(chunk)
                chunk = source.read(_CHUNK)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != payload["sha256"]:
            raise RuntimeError(
                f"{_PACKAGE / 'bifrost.xz'} unpacks to SHA-256 {digest.hexdigest()}, "
                f"expected {payload['sha256']}; reinstall brokk-bifrost"
            )
        os.chmod(temporary, 0o755)
        try:
            os.replace(temporary, target)
        except PermissionError:
            # Windows refuses to replace an executable that a concurrent first
            # run has already started. That run placed a verified copy.
            if not _is_unpacked(target, payload):
                raise
        _fsync_directory(directory)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    if parent == _PACKAGE:
        _remove_other_copies(directory)
    return target


def _is_unpacked(target, payload):
    try:
        return target.stat().st_size == payload["size"]
    except FileNotFoundError:
        return False


def _fsync_directory(directory):
    # Make the rename durable. Windows cannot open a directory for fsync, and
    # its rename is already durable once it returns.
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_other_copies(current):
    for stale in _PACKAGE.glob("bin-*"):
        if stale == current:
            continue
        try:
            shutil.rmtree(stale)
        except PermissionError:
            # A copy that is still running on Windows cannot be removed yet;
            # the next unpack in this installation tries again.
            continue


def _cache_directory():
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "brokk-bifrost"


if __name__ == "__main__":
    main()
