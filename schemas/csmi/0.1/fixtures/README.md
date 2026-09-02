# CSMI v0.1 fixtures

The fixture groups exercise different conformance boundaries:

- `valid/` contains structurally valid representative documents with no
  intentionally embedded semantic violation. Manifest resource bytes are not
  materialized by these standalone schema fixtures.
- `invalid/` contains structurally invalid documents. Every file must be
  rejected by `spec/0.1/schema.json`.
- `semantic-invalid/` contains documents that intentionally pass JSON Schema
  but violate a named semantic invariant from the specification.

The last group is important: successful JSON Schema validation establishes
structure only. It does not resolve symbol references, prove artifact
applicability, establish profile support, or license closed-world inference.

Run all structural fixture expectations with:

```sh
python3 scripts/validate-schema.py
```
