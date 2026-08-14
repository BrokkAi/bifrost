# Sanitizer semantic packs

These packs carry Bifrost's audited sanitizer content (#1871 Stage 4, #1923).
Each pack is a `procedure_summaries` pack. Each summary states that one method
neutralizes taint for a set of injection contexts. The pack removes the matching
taint labels on the modeled value flow.

The content comes from the audited k3 sanitizer candidates in
`.agents/foundry/candidates/sanitizers/`. The converter reads those candidates,
gates each one, and writes the packs and the audit report here. Do not edit the
generated files by hand. Change the candidates and regenerate.

## Shipping model

Each candidate carries one audited claim: `neutralizes` (the contexts the method
makes safe) and `does_not_neutralize` (the contexts it does not). The converter
maps that claim onto the #1923 pack shape:

- `neutralizes` becomes a `Sanitize` effect's `removes` labels. Each context
  token (`sql`, `html`, `log`, and the rest) is a taint label.
- `sanitized_input` becomes the effect `input` port.
- `output` becomes the effect `output` port.
- The target comes from the candidate.

A `Sanitize` effect must ride a declared transfer with the same ports, so each
summary also carries the matching `input -> output` transfer. The labels under
`does_not_neutralize` are the labels the transfer leaves flowing, because they
are absent from `removes`.

## The adversarial gate

Every candidate runs through the M4 adversarial mechanism gate
(`gate_sanitizer`). The gate expresses each `neutralizes` context as a probe
over that context's real breakout metacharacter (for example `'` for `sql`) and
each `does_not_neutralize` context as a survival probe. A candidate that fails
the gate is never shipped on its assertion; the audit report records it.

Shipping rests on the audited judgment plus this mechanism proof. Proof that a
real escaper body actually encodes the breakout metacharacter is a separate M4
seam and a tracked follow-up. It is not required here.

## Pack organization

There is one pack per artifact, the same way the declaration packs
(`bifrost.jdk`, `kotlin-stdlib`, `scala-library`, `typeshed-stdlib`) are one
pack per artifact. A pack pins one artifact.

| pack | artifact | pinned | summaries |
| --- | --- | --- | --- |
| `bifrost.java-sanitizers` | jdk | yes (jdk toolchain) | 11 |
| `staged/bifrost.guava-sanitizers` | com.google.guava:guava:33.6.0-jre | no | 5 |
| `staged/bifrost.commons-text-sanitizers` | org.apache.commons:commons-text:1.15.0 | no | 7 |
| `staged/bifrost.encoder-sanitizers` | org.owasp.encoder:encoder:1.4.0 | no | 15 |
| `staged/bifrost.esapi-sanitizers` | org.owasp.esapi:esapi:2.7.0.0 | no | 13 |
| `staged/bifrost.spring-web-sanitizers` | org.springframework:spring-web:7.0.8 | no | 5 |

`bifrost.java-sanitizers` is the first real shipped pack. It activates on the
`jdk` toolchain. That is a genuine pin, not a byte digest. The JDK APIs it names
(`Integer.parseInt`, `Base64`, `URLEncoder`, `UUID`) exist in Java 17 and later.

The five library packs target external Maven coordinates. A byte-level artifact
digest (`artifact_sha256`) needs the library jar, which is not available here.
Bifrost does not ship a faked pin. So the library packs are generated and
**staged unpinned** under `staged/`: each activates on its package coordinate,
with no `artifact_sha256`. A future step downloads and digests each jar, adds
the pin, and promotes the pack out of `staged/`.

## Folded overloads

The audited symbols carry no parameter-type signature, so two overloads of one
method (for example `Integer.parseInt(String)` and
`Integer.parseInt(String,int)`) share one `(path, symbol)` target. A pack cannot
carry two summaries on one target. When the overloads carry an identical claim,
the converter folds them into one summary and records the fold in the audit
report. When two overloads disagree, the converter refuses rather than pick one.

## Audit report

`rejects.json` is the audit outcome. It records the candidate total, the gate
rejects with their reasons, the folded overloads, the shipped totals, the
adversarial-probe count, and one line per pack. It is deterministic and clock
free.

## Regeneration

The converter is deterministic. Two runs over the same candidates produce
byte-identical output.

```console
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- \
  sanitizer-pack .agents/foundry/candidates/sanitizers semantic-packs/sanitizers
```

`tests/suite_bench_policy/sanitizer_pack_shipping.rs` proves the checked-in
files match the converter, every pack compiles through the production compiler,
and a shipped sanitizer neutralizes end to end through the production taint
route.
