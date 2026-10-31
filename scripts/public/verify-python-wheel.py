#!/usr/bin/env python3
"""Install one staged wheel and exercise its shipped public entrypoint."""

import argparse
from email.parser import Parser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import venv
import zipfile


def verify(wheel_directory: Path, kind: str, version: str) -> None:
    """Check one staged wheel's metadata, then install it in a fresh venv and exercise it."""
    prefix = "brokk_bifrost_searchtools" if kind == "client" else "brokk_bifrost"
    wheels = list(wheel_directory.resolve().glob(f"{prefix}-{version}-*.whl"))
    assert len(wheels) == 1, f"Expected one {kind} wheel, found {wheels}"
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        assert len(metadata) == 1, metadata
        fields = Parser().parsestr(archive.read(metadata[0]).decode())
        expected_name = "brokk-bifrost-searchtools" if kind == "client" else "brokk-bifrost"
        assert fields["Name"] == expected_name, fields["Name"]
        assert fields["Version"] == version, fields["Version"]
        licenses = fields.get_all("License-File", [])
        assert any(name.endswith("LICENSE.md") for name in licenses), licenses
        assert any(name.endswith("THIRD_PARTY_LICENSES.html") for name in licenses), licenses
        assert any(name.endswith("SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt") for name in licenses), licenses
        for name in licenses:
            packaged = f"{Path(metadata[0]).parent.as_posix()}/licenses/{name}"
            assert packaged in archive.namelist(), packaged
            assert archive.read(packaged), f"Empty license notice: {packaged}"
        if kind == "cli":
            verify_compressed_cli_layout(archive, Path(metadata[0]).parent.as_posix())

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["BIFROST_OPEN_PACKS_OFFLINE"] = "1"
    with tempfile.TemporaryDirectory(prefix="bifrost-wheel-smoke-") as temporary:
        root = Path(temporary)
        install = root / "venv"
        venv.EnvBuilder(with_pip=True, symlinks=os.name != "nt").create(install)
        scripts = install / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")

        # python.org's macOS Python is universal2, so on Apple silicon it runs as
        # arm64 and pip refuses an x86_64 wheel. Run the venv's interpreter
        # under Rosetta for an x86_64 wheel; processes it starts inherit the
        # architecture, so the installed x86_64 artifact is what executes.
        launcher = (["arch", "-x86_64"] if sys.platform == "darwin"
                    and wheel.name.endswith("_x86_64.whl") else [])

        def run(command: list[str]) -> subprocess.CompletedProcess:
            result = subprocess.run(command, cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=180)
            assert result.returncode == 0, (
                f"{command} exited {result.returncode}\n{result.stdout}\n{result.stderr}"
            )
            return result

        if launcher:
            machine = run([*launcher, str(python), "-I", "-c",
                           "import platform; print(platform.machine())"]).stdout.strip()
            assert machine == "x86_64", f"x86_64 wheel smoke runs on {machine}"
        run([*launcher, str(python), "-I", "-m", "pip", "install", "--no-cache-dir", "--no-index",
             "--no-deps", str(wheel)])
        if kind == "client":
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "hello.py").write_text('def greet(name: str) -> str:\n    return "hello " + name\n')
            run(["git", "init", "--quiet", str(fixture)])
            run(["git", "-C", str(fixture), "add", "hello.py"])
            probe = '''import importlib.metadata, json, sys
import bifrost_searchtools
from bifrost_searchtools import SearchToolsClient, _native
assert importlib.metadata.version("brokk-bifrost-searchtools") == sys.argv[2]
assert "site-packages" in bifrost_searchtools.__file__, bifrost_searchtools.__file__
assert "site-packages" in _native.__file__, _native.__file__
with SearchToolsClient(sys.argv[1], manual=True) as client:
    result = client.search_symbols(["greet"], limit=10)
    assert result.count == 1, result.render_text()
    assert "greet" in result.render_text(), result.render_text()
print(json.dumps({"package": bifrost_searchtools.__file__, "native": _native.__file__}))
'''
            print(run([*launcher, str(python), "-I", "-c", probe, str(fixture), version]).stdout,
                  end="")
        else:
            binary = exercise_cli_launchers(root, scripts, python, launcher, environment, version, run)
            probe = Path(__file__).with_name("verify-engine-compatibility.mjs")
            print(run(["node", str(probe), str(binary), "--engine-version", version]).stdout, end="")
        print(json.dumps({"wheel": str(wheel), "kind": kind, "version": version,
                          "status": "installed-and-exercised"}))


def verify_compressed_cli_layout(archive: zipfile.ZipFile, dist_info: str) -> None:
    """The CLI wheel carries its binary xz-compressed behind the launcher (#8288)."""
    names = archive.namelist()
    raw = [name for name in names if ".data/scripts/" in name]
    assert not raw, f"the CLI wheel must not ship raw scripts or binaries: {raw}"
    for name in ("brokk_bifrost_cli/__init__.py", "brokk_bifrost_cli/payload.json",
                 "brokk_bifrost_cli/bifrost.xz"):
        assert name in names, f"missing {name}: {names}"
    assert archive.getinfo("brokk_bifrost_cli/bifrost.xz").compress_type == zipfile.ZIP_STORED
    entry_points = archive.read(f"{dist_info}/entry_points.txt").decode()
    for command in ("bifrost", "brokk-bifrost"):
        assert f"{command} = brokk_bifrost_cli:main" in entry_points, entry_points


def exercise_cli_launchers(root, scripts, python, launcher, environment, version, run):
    """Run the launcher the way users meet it, and return the unpacked binary.

    A read-only installation unpacks into the per-user cache. Two concurrent
    first runs in a writable installation both succeed, and a second run
    reuses the unpacked copy.
    """
    suffix = ".exe" if os.name == "nt" else ""
    commands = [str(scripts / f"bifrost{suffix}"), str(scripts / f"brokk-bifrost{suffix}")]
    package = Path(run([*launcher, str(python), "-I", "-c",
                        "import brokk_bifrost_cli, os; print(os.path.dirname(brokk_bifrost_cli.__file__))"]
                       ).stdout.strip())
    expected = f"bifrost {version}"
    timings = {}

    def check(result, label):
        output = result.stdout.splitlines()
        assert output and output[0] == expected, f"{label}: {output}"

    # chmod cannot make a directory read-only on Windows or for root.
    if os.name != "nt" and os.geteuid() != 0:
        cache_home = root / "cache-home"
        read_only = dict(environment, HOME=str(cache_home), XDG_CACHE_HOME=str(cache_home / ".cache"))
        package.chmod(0o555)
        try:
            check(subprocess.run([commands[0], "--version"], cwd=root, env=read_only, text=True,
                                 capture_output=True, timeout=180, check=True), "read-only install")
        finally:
            package.chmod(0o755)
        cached = list(cache_home.glob("**/brokk-bifrost/bin-*/bifrost"))
        assert len(cached) == 1, f"a read-only install must unpack into the user cache: {cached}"
        assert not list(package.glob("bin-*")), "a read-only install must not unpack beside the payload"

    started = time.monotonic()
    first_runs = [subprocess.Popen([command, "--version"], cwd=root, env=environment, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                  for command in commands]
    for command, process in zip(commands, first_runs):
        stdout, stderr = process.communicate(timeout=300)
        assert process.returncode == 0, f"concurrent first run {command} exited {process.returncode}\n{stderr}"
        check(subprocess.CompletedProcess(command, 0, stdout, stderr), f"concurrent first run {command}")
    timings["concurrent_first_runs_seconds"] = round(time.monotonic() - started, 2)

    started = time.monotonic()
    check(run([commands[0], "--version"]), "second run")
    timings["second_run_seconds"] = round(time.monotonic() - started, 2)

    unpacked = list(package.glob(f"bin-*/bifrost{suffix}"))
    assert len(unpacked) == 1, f"expected one unpacked binary beside the payload: {unpacked}"
    leftovers = [path for path in package.glob("bin-*/*") if path != unpacked[0]]
    assert not leftovers, f"unpacking left temporary files behind: {leftovers}"
    if os.name != "nt":
        assert os.access(unpacked[0], os.X_OK), unpacked[0]
    print(json.dumps({"unpacked": str(unpacked[0]), **timings}))
    return unpacked[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-directory", type=Path, required=True)
    parser.add_argument("--kind", choices=("client", "cli"), required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    verify(arguments.wheel_directory, arguments.kind, arguments.version)
