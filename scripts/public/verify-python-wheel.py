#!/usr/bin/env python3
"""Install one staged wheel and exercise its shipped public entrypoint."""

import argparse
from email.parser import Parser
import json
import os
from pathlib import Path
import subprocess
import tempfile
import venv
import zipfile


def verify(wheel_directory: Path, kind: str, version: str) -> None:
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

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment["BIFROST_OPEN_PACKS_OFFLINE"] = "1"
    with tempfile.TemporaryDirectory(prefix="bifrost-wheel-smoke-") as temporary:
        root = Path(temporary)
        install = root / "venv"
        venv.EnvBuilder(with_pip=True, symlinks=os.name != "nt").create(install)
        scripts = install / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")

        def run(command: list[str]) -> subprocess.CompletedProcess:
            result = subprocess.run(command, cwd=root, env=environment,
                                    text=True, capture_output=True, timeout=180)
            assert result.returncode == 0, (
                f"{command} exited {result.returncode}\n{result.stdout}\n{result.stderr}"
            )
            return result

        run([str(python), "-I", "-m", "pip", "install", "--no-cache-dir", "--no-index",
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
            print(run([str(python), "-I", "-c", probe, str(fixture), version]).stdout, end="")
        else:
            wrapper = scripts / ("brokk-bifrost.cmd" if os.name == "nt" else "brokk-bifrost")
            command = [str(wrapper), "--version"]
            if os.name == "nt":
                command = ["cmd.exe", "/c", *command]
            output = run(command).stdout.splitlines()
            assert output and output[0] == f"bifrost {version}", output
            binary = scripts / ("bifrost.exe" if os.name == "nt" else "bifrost")
            probe = Path(__file__).with_name("verify-engine-compatibility.mjs")
            print(run(["node", str(probe), str(binary), "--engine-version", version]).stdout, end="")
        print(json.dumps({"wheel": str(wheel), "kind": kind, "version": version,
                          "status": "installed-and-exercised"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-directory", type=Path, required=True)
    parser.add_argument("--kind", choices=("client", "cli"), required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    verify(arguments.wheel_directory, arguments.kind, arguments.version)
