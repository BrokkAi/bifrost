"""Regenerate small, explicitly synthetic compiler archives for #12213 tests."""
import copy
import io
import json
import lzma
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
sources = root.parent / "rustdoc-contract"
for scenario in ("verified", "ambiguous"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
        def append(name, data):
            member = tarfile.TarInfo("dist/" + name)
            member.mode = 0o644
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))

        append("version", b"1.0.0 (000000000 2026-08-23)")
        append("git-commit-hash", b"0" * 40)
        append("components", b"rust-docs-json-preview\n")
        for name in ("core", "alloc", "std"):
            doc = json.loads((sources / (name + ".json")).read_bytes())
            doc["crate_version"] = None
            if name == "alloc":
                impl = doc["index"]["51"]["inner"]["impl"]
                impl["blanket_impl"] = None
                impl["generics"] = {"params": [], "where_predicates": []}
                impl["for"] = {"resolved_path": {"path": "Box", "id": 50, "args": None}}
                impl["items"] = []
            if name == "core" and scenario == "ambiguous":
                key, summary = next((k, v) for k, v in doc["paths"].items() if v["path"] == ["core", "Traverse"])
                item = copy.deepcopy(doc["index"][key])
                item["id"] = 999999
                doc["index"]["999999"] = item
                doc["paths"]["999999"] = summary
            append("rust-docs-json-preview/share/doc/rust/json/" + name + ".json",
                   json.dumps(doc, separators=(",", ":")).encode())
    (root / (scenario + ".tar.xz")).write_bytes(lzma.compress(output.getvalue(), preset=0))
