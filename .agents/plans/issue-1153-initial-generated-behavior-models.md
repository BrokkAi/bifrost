# Ship the first generated behavior models

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost must understand selected generated declarations without running a compiler, macro, or annotation processor.

After this work, common semantic-model rules will provide four curated behavior groups. They cover Scala case classes, Lombok, one workspace macro, and getset.

Each result will include exact activation evidence and deterministic provenance. Generated navigation will return an authored declaration or a stable model URI.

The focused semantic-model tests and UsageBench cases will show the result. Negative cases will prove that same-name and wrong-version inputs do not match.

## Progress

- [x] (2026-08-04 15:25 +0200) Read the task, repository rules, and `.agents/PLANS.md`.
- [x] (2026-08-04 15:25 +0200) Fetched Bifrost and UsageBench. Recorded Bifrost `a97b50c0d` and UsageBench `23c13e4f`.
- [x] (2026-08-04 15:25 +0200) Verified live issues. Issue #1151 is closed, and issue #1153 is open.
- [x] (2026-08-04 15:25 +0200) Verified the #1151 tools. Six authoring tests and three conformance tests pass.
- [x] (2026-08-04 15:25 +0200) Selected getset 0.1.7 for the non-JVM research fixture, subject to a measured miss.
- [x] (2026-08-04 17:48 +0200) Implement Milestone 1. Added grammar-backed construct facts, repeated scalar rows, authored anchors, exact receiver lookup, inverse references, shipped-pack composition, and workspace activation.
- [x] (2026-08-04 17:48 +0200) Reviewed Milestone 1. Corrected deferred MCP activation, authoring reachability, anchor validation, and provenance assertions.
- [x] (2026-08-04 18:02 +0200) Implement Milestone 2. Shipped Scala `copy` and ordered constructor-parameter accessor rules with exact source anchors.
- [x] (2026-08-04 18:02 +0200) Reviewed Milestone 2. Added record-level provenance checks and proved forward and inverse resolution.
- [x] (2026-08-04 19:34 +0200) Implement Milestone 3. Shipped exact Lombok 1.18.42 getters and setters with authored field anchors.
- [x] (2026-08-04 19:34 +0200) Review Milestone 3. Removed legacy Lombok paths and corrected call shape, method-reference, field-modifier, and reverse-navigation behavior.
- [ ] Commit Milestone 3 with a multiline checkpoint message.
- [ ] Implement Milestone 4. Activate the UsageBench workspace rule and pass its Rust case.
- [ ] Review and commit Milestone 4 with a multiline checkpoint message.
- [ ] Implement Milestone 5. Measure, ship, and prove the getset 0.1.7 model.
- [ ] Review and commit Milestone 5 with a multiline checkpoint message.
- [ ] Run package checks, UsageBench cases, policy checks, formatting, and the applicable Rust gates.
- [ ] Complete the final specialist review. Correct each accepted finding and commit the review changes.

## Surprises & Discoveries

- Observation: The #1151 tools are present and use the production compiler and matcher.
  Evidence: `semantic_model_authoring` passed six tests. `semantic_model_conformance` passed three tests.

- Observation: The schema declares `Arguments`, `ResolvedOwner`, `ResolvedCall`, and `Many` captures.
  Evidence: `overlay.rs` currently returns no value for these sources. It also ignores a present `Many` value.

- Observation: The MCP host does not load repository-local model files.
  Evidence: `searchtools_service.rs` only opens the configured catalog and parses configured evidence.

- Observation: The current Lombok path accepts short annotation names.
  Evidence: `java_lombok_annotation_generates_accessor` matches `Getter`, `Setter`, `Data`, and `Value` without owner evidence.

- Observation: getset 0.1.7 has direct Bifrost product evidence.
  Evidence: Bifrost uses jclassfile 0.6.0. Four jclassfile source modules use getset-generated getters.

- Observation: Runtime selection already had a language evidence rank, but validation rejected its empty coordinate selector.
  Evidence: `selector_rank` returns `EvidenceRank::Language`. The validator now permits this explicit intrinsic form.

- Observation: Deferred MCP construction bypassed both configured and shipped model activation.
  Evidence: The post-milestone review found the direct persisted builder. The deferred thread now runs the common activation function.

- Observation: Generated signatures rendered correctly but did not retain their structured form.
  Evidence: A zero-argument Lombok getter initially accepted a one-argument call. The overlay now evaluates template signatures into typed signatures.

- Observation: An authored backing-field usage scan did not include generated accessor calls.
  Evidence: The generic inverse bridge resolved model symbols only. It now follows inbound `navigates_to` relations to generated members.

## Decision Log

- Decision: Keep behavior in semantic-model rules. Add only general structured facts to language adapters.
  Rationale: The task prohibits language-specific generated-member resolution paths.
  Date/Author: 2026-08-04 / Codex

- Decision: Keep authored source, exact artifacts, and modeled facts in that precedence order.
  Rationale: A rule must augment missing declarations. It must not replace real declarations.
  Date/Author: 2026-08-04 / Codex

- Decision: Use workspace, installed, and shipped model precedence in that order.
  Rationale: This is the existing semantic-model activation contract.
  Date/Author: 2026-08-04 / Codex

- Decision: Use getset 0.1.7 as the pinned non-JVM candidate after a measured miss.
  Rationale: The exact version is locked. Bifrost depends on a crate that uses its generated getters.
  Date/Author: 2026-08-04 / Codex

- Decision: Keep `define_job_maker!` as a workspace-only rule.
  Rationale: The rule describes one repository macro. It does not claim general `macro_rules!` expansion.
  Date/Author: 2026-08-04 / Codex

- Decision: Zip repeated captures by source order into scalar rows.
  Rationale: One row carries the parameter name, stable identity, and authored anchor. Templates remain scalar and deterministic.
  Date/Author: 2026-08-04 / Codex

- Decision: Publish Java field modifier facts in signature metadata.
  Rationale: Static fields must not produce instance accessors. Final fields must not produce setters. Structured metadata keeps this rule out of source text scans.
  Date/Author: 2026-08-04 / Codex

- Decision: Resolve short annotation names only through one exact structured import.
  Rationale: A duplicate local import is ambiguous. A same-name annotation from another owner must not activate a Lombok rule.
  Date/Author: 2026-08-04 / Codex

## Outcomes & Retrospective

Three Bifrost milestones are implemented. The runtime substrate, Scala case-class pack, and exact Lombok pack pass focused tests.

The Lombok migration removed special definition, source, and usage behavior. The common semantic overlay now handles these paths.

## Context and Orientation

A semantic-model pack is reviewed YAML or JSON. The compiler converts it to deterministic, typed artifacts.

`crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines the authoring types. `compiler.rs` creates canonical artifacts. `validate.rs` checks them.

`overlay.rs` matches active rules against normalized syntax. It emits declarations, aliases, relationships, provenance, and stable model locations.

`runtime.rs` selects active shards once per analyzer generation. `catalog/` stores installed and session packs.

`authoring.rs` validates workspace models under `.bifrost/semantic-models`. The production hosts do not yet activate these files.

`crates/bifrost-semantic-packs` owns curated shipped content. `brokk-bifrost-analysis` must not depend on this distribution crate.

Language adapters already supply normalized structural facts. They can add general generator facts from tree-sitter nodes.

An authored anchor is a real source location. A model URI is a stable `bifrost-model://` location without fake source.

The Scala resolver has special case-class logic. The Java resolver and Java usage graph have special Lombok logic.

This work must remove generated behavior from those special paths. General adapter facts can remain language-specific.

UsageBench current main is `23c13e4f866b60ed17a07814d408b960aed160df`. Its Scala and Rust cases already contain exact source ranges.

## Plan of Work

### Milestone 1: Complete the common generator-rule path

Extend the authoring model with bounded, ordered generator-site facts. A fact must expose scalar values and repeated authored declarations.

Add a repeated emission form. It will bind one structured row for each authored child. It must preserve source order.

Add source-anchor templates. A generated declaration can point to the matched declaration or a repeated child declaration.

Use the existing model URI when no honest authored anchor exists. Keep URI construction portable and deterministic.

Resolve annotation and derive owners through structured AST paths and import bindings. Do not scan source text.

Add receiver-aware overlay lookup. A generated member match must use its owner identity, name, and callable shape.

Add a generic authored-hit bridge for `navigates_to` and `references`. Search, definition, and inverse usage must use the same relations.

Compose three pack sources in the facade or host. Load shipped content, installed content, and explicit workspace content.

Do not make `brokk-bifrost-analysis` depend on `brokk-bifrost-semantic-packs`.

Add compiler, validation, matcher, overlay, provenance, corruption, precedence, cold activation, and warm reacquisition tests.

### Milestone 2: Ship Scala case-class intrinsic behavior

Add structured Scala case-class and constructor-parameter facts. Use tree-sitter fields and declaration ranges only.

Create a shipped Scala rule pack. It will emit companion construction where needed, `copy`, and parameter accessors.

Emit named `copy` parameter relationships. Map `copy` to the class anchor. Map each accessor to its constructor parameter.

Keep the existing correct construction result. Remove only superseded special generated behavior.

Prove real declaration precedence. Add conflicting `copy` and accessor fixtures.

Run the two exact Scala UsageBench cases. Forward definitions and inverse usages must agree.

### Milestone 3: Ship exact Lombok behavior

Add shipped rules for supported `lombok.Getter`, `lombok.Setter`, `lombok.Data`, and `lombok.Value` forms.

Select the exact supported version range from a pinned fixture. Record the coordinate and artifact evidence.

Match fully qualified annotation owners. Short forms must resolve through exact imports.

Emit getters and setters from exact backing fields. Map each member and reference to the backing field anchor.

Remove the old short-name Lombok resolution and usage paths after model tests pass.

Test exact-version positives, wrong-package names, wrong versions, absent dependencies, and declared-method precedence.

### Milestone 4: Activate the UsageBench workspace rule

Add `.bifrost/semantic-models` content to the UsageBench Rust fixture. The rule will match only `define_job_maker!`.

Add an explicit UsageBench case option for workspace-model activation. Keep its schema strict and deterministic.

Pass that option to Bifrost. Load only the named workspace model from the fixture root.

Emit `generated_job` from the macro argument. Use the macro argument as its authored anchor.

Prove definition and inverse usage results. Keep other same-name macros inactive.

Remove `expectedFailure` only after the exact UsageBench case passes.

Commit UsageBench changes in its repository. Keep the commit separate from Bifrost commits.

### Milestone 5: Ship getset 0.1.7 behavior

Create a pinned Rust fixture that uses `getset = "=0.1.7"`. Reproduce a missing getter definition and inverse usage first.

Use Bifrost product evidence in jclassfile 0.6.0. The fixture will cover one supported getter form only.

Ship a dependency-qualified getset rule. Match the exact derive owner and required field attribute.

Map the generated getter to its backing field. Do not claim unsupported prefixes, skips, tuple fields, or other derive modes.

Test the exact version, wrong owner, unsupported version, absent dependency, and real method precedence.

Record the active pack, rule, digest, model URI, and authored anchor in test evidence.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/86d5/bifrost` unless stated otherwise.

Before each milestone, run:

    git status --short --branch
    git rev-parse HEAD

After common model changes, run focused tests:

    cargo test --test suite_semantic semantic_model_pack
    cargo test --test suite_semantic semantic_model_runtime
    cargo test --test suite_semantic semantic_model_overlay
    cargo test --test suite_semantic semantic_model_authoring
    cargo test --test suite_semantic semantic_model_conformance

After Scala changes, run focused Scala definition and usage tests. Also run both named UsageBench cases.

After Lombok changes, run focused Java definition, source, and usage tests. Include all positive and negative model tests.

After workspace changes, run `rust-parity-macro-generated-function-reference` from UsageBench `origin/main` content.

After getset changes, run its focused Rust model tests and the shipped-pack package checks.

Run `cargo fmt` before each checkpoint commit. Run `git diff --check` after formatting.

Stage only milestone files. Use a multiline checkpoint commit that explains the design and validation.

Before final completion, run the installed policy tool once with all required policy sources together.

Run the affected package and release checks. Use `scripts/with-isolated-cargo-target.sh` for an all-feature Clippy run.

Do not enable NLP for routine focused tests. Check disk space before an authorized all-feature build.

## Validation and Acceptance

The compiler must reject unknown, corrupt, and incompatible model content. Deterministic input must produce identical artifacts and provenance.

Language intrinsic activation must select the Scala pack without dependency evidence. The active report must identify shipped content.

Dependency activation must select Lombok and getset only with exact supported coordinates. Wrong or absent evidence must select nothing.

Workspace activation must require explicit opt-in. Its provenance must identify an ephemeral workspace source and content hash.

Real declarations must win over modeled facts. Workspace models must win over installed and shipped models.

Scala `copy` must navigate to the case-class declaration. Each component accessor must navigate to its constructor parameter.

Lombok and getset accessors must navigate to exact backing fields. Same-name wrong-owner annotations must miss.

The UsageBench macro call must navigate to the macro argument. Inverse usage must return the generated call site.

Cold activation and warm reacquisition must return the same active hash, rule IDs, facts, relationships, and locations.

Policy status `finding` requires review or correction. Policy status `unreliable` fails validation.

## Idempotence and Recovery

All focused tests and compilers are safe to run again. Content-addressed pack registration must remain idempotent.

Do not delete catalog data during tests. Use ephemeral catalogs and `InlineTestProject` fixtures.

If a milestone fails, keep its changes unstaged. Update this plan with the exact failure and next repair.

Do not switch branches, rebase, push, or open a pull request. Commit only the files from each completed milestone.

UsageBench has a different repository. Never stage its files from the Bifrost worktree.

## Artifacts and Notes

Initial Bifrost revision:

    a97b50c0d30853af8ea66713541b90ac169cff45

Initial UsageBench revision:

    23c13e4f866b60ed17a07814d408b960aed160df

Dependency gate:

    semantic_model_authoring: 6 passed
    semantic_model_conformance: 3 passed

Selected non-JVM evidence:

    Bifrost -> jclassfile 0.6.0 -> getset 0.1.7
    jclassfile modules with Getters or CopyGetters: class_file.rs, fields.rs, attributes.rs, methods.rs

The first Bifrost code-intelligence calls completed below five seconds. One diagnostic agent saw `most_relevant_files` complete in 5.587 seconds.

## Interfaces and Dependencies

The final authoring API must represent a bounded repeated declaration capture. It must expose stable identity, name, type, owner, and source anchor.

The final emission API must repeat over one ordered capture. Nested unbounded repetition is not required.

The final matcher API must accept structured generator-site facts. It must return exact captures or the first failed predicate.

The final overlay API must resolve generated members by owner and callable shape. It must expose authored relations generically.

The semantic-packs crate must expose a small curated behavior registry. The facade or host will register it into the analysis catalog.

Workspace loading must reuse `discover_workspace_semantic_models`, `compile_source`, and existing catalog session sources.

No model can execute code. No model can read outside its approved workspace path.

Plan revision note (2026-08-04): Created the initial plan after the live issue and dependency checks. The design follows observed runtime gaps.
