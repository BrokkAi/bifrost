"""Unpack the file that a Brokk wheel ships xz-compressed.

PyPI caps a file at 100 MiB. The bifrost CLI binary and the searchtools
extension module are each about 300 MB, so their wheels carry the file
xz-compressed beside ``payload.json``, which records the unpacked file's name,
the compressed file's name, and the unpacked file's SHA-256 and size as they
were when the wheel was built (#8288). ``unpacked_file`` unpacks it once and
returns its path.

scripts/public/compress-python-wheel.py copies this module into each wheel it
rewrites, as ``<package>/_xz_payload.py``. The two wheels install
independently, so they cannot import one shared copy; this file is the single
source of both.

Where the file goes: ``bin-<digest>/`` beside the payload, so the copy lives
and is upgraded with the installation, or, when site-packages is read-only (a
system or image install), the per-user cache directory. The digest in the
directory name makes a wheel with a different file unpack its own copy, and
keeps the file's own name. A wheel of a new version whose file is
byte-identical reuses the copy, because it is the same file. ``pip
uninstall`` does not know about the unpacked copy and leaves ``bin-<digest>/``
behind; a later unpack in this directory removes copies of other digests.
Copies in the shared cache are never removed, because another installation may
be about to use them.

Only a verified copy ever reaches its final path: the file is decompressed
into a temporary file in the same directory, hashed while it is written,
fsynced and renamed into place. Concurrent first uses each unpack their own
temporary file and the renames are atomic, so every use sees either no file
or a complete one. A later use therefore checks the size alone.

This module uses only the standard library, for every Python either wheel
supports (3.8 and later).
"""

import errno
import hashlib
import json
import lzma
import os
import shutil
import sys
import tempfile
from pathlib import Path

_CHUNK = 1 << 20
# A directory we cannot write to: try the next location.
_UNWRITABLE = (errno.EACCES, errno.EPERM, errno.EROFS)


def unpacked_file(package, cache_name):
    """Return the verified, unpacked payload of ``package``, unpacking it on first use.

    ``package`` is the directory holding ``payload.json`` and the compressed
    file; ``cache_name`` names the per-user cache directory used when
    ``package`` is read-only.
    """
    payload = json.loads((package / "payload.json").read_text(encoding="utf-8"))
    directory_name = f"bin-{payload['sha256'][:16]}"
    try:
        return _unpack_into(package, package, directory_name, payload)
    except OSError as error:
        if error.errno not in _UNWRITABLE:
            raise
    return _unpack_into(package, _cache_directory(cache_name), directory_name, payload)


def _unpack_into(package, parent, directory_name, payload):
    directory = parent / directory_name
    target = directory / payload["file"]
    if _is_unpacked(target, payload):
        return target
    compressed = package / payload["compressed"]
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{payload['file']}.", dir=directory)
    try:
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as output, lzma.open(compressed) as source:
            chunk = source.read(_CHUNK)
            while chunk:
                digest.update(chunk)
                output.write(chunk)
                chunk = source.read(_CHUNK)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != payload["sha256"]:
            raise RuntimeError(
                f"{compressed} unpacks to SHA-256 {digest.hexdigest()}, "
                f"expected {payload['sha256']}; reinstall the package"
            )
        os.chmod(temporary, 0o755)
        try:
            os.replace(temporary, target)
        except PermissionError:
            # Windows refuses to replace an executable or a DLL that a
            # concurrent first use has already loaded. That use placed a
            # verified copy.
            if not _is_unpacked(target, payload):
                raise
        _fsync_directory(directory)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    if parent == package:
        _remove_other_copies(package, directory)
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


def _remove_other_copies(package, current):
    for stale in package.glob("bin-*"):
        if stale == current:
            continue
        try:
            shutil.rmtree(stale)
        except PermissionError:
            # A copy that is still in use on Windows cannot be removed yet;
            # the next unpack in this installation tries again.
            continue


def _cache_directory(cache_name):
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / cache_name
