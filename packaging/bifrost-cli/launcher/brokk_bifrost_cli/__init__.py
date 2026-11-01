"""Run the bifrost binary that the brokk-bifrost wheel ships xz-compressed.

The binary is about 300 MB and PyPI caps a file at 100 MiB, so the wheel
carries ``bifrost.xz`` and ``payload.json`` instead of the binary. The
``bifrost`` and ``brokk-bifrost`` console scripts call ``main``, which unpacks
the binary once and then replaces this process with it. ``_xz_payload``, which
scripts/public/compress-python-wheel.py copies into the wheel from
packaging/xz-payload, describes where the binary goes and how the unpack stays
safe under concurrent first runs.

This module uses only the standard library, for every Python the wheel
supports (3.8 and later).
"""

import os
import signal
import subprocess
import sys
from pathlib import Path

from . import _xz_payload

_PACKAGE = Path(__file__).resolve().parent


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
    return _xz_payload.unpacked_file(_PACKAGE, "brokk-bifrost")

