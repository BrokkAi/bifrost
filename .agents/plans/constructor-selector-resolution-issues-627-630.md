# Make constructor selectors resolve consistently

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Users should be able to ask for a class by its ordinary name without being forced to choose between the class and that class's explicit constructor. C# users should also be able to use the conventional metadata spelling `#ctor` and receive the source of an explicit constructor. After this change, a bare Java type query such as `CompressionBodyRequestFilter` resolves to the type, while `org.example.CompressionBodyRequestFilter.CompressionBodyRequestFilter` still resolves to its constructor; a C# query such as `NzbDrone.Core.Organizer.FileNameBuilder.#ctor` resolves to the same constructor as the existing canonical repeated-name selector.

## Progress

- [x] (2026-07-11 12:48Z) Read issues #627 and #630, reproduced their resolution paths in the current source, and confirmed both reports are valid.
- [x] (2026-07-11 12:48Z) Mapped the shared symbol lookup, selectable-definition grouping, file-anchor parsing, and C# name-normalization paths.
- [x] (2026-07-11 12:56Z) Added behavior-focused inline-project regressions for Java type/constructor precedence, real same-name type ambiguity, C# `#ctor` overload lookup, anchored lookup, and absent implicit constructors.
- [x] (2026-07-11 12:56Z) Implemented structured shared fuzzy precedence for Java/C#/C++ and C# terminal `.#ctor` normalization without changing constructor indexing.
- [x] (2026-07-11 12:56Z) Ran both focused test binaries, `cargo fmt --check`, `cargo clippy-no-cuda`, `git diff --check`, and the complete default `cargo test` suite successfully.
- [ ] Review the final diff for cross-language selector regressions, commit and push only files changed for these issues, then close GitHub issues #627 and #630.

## Surprises & Discoveries

- Observation: Issue #627 is not caused by synthetic constructors. Commit `c4dc1d54` already removed implicit Java constructor `CodeUnit`s; the reported collision is between a real class and a real explicit constructor with canonical names `pkg.Type` and `pkg.Type.Type`.
  Evidence: `src/analyzer/symbol_lookup.rs::codeunit_lookup_aliases` includes each declaration's identifier, so both declarations match the bare identifier `Type`.

- Observation: Issue #630 fails before C# symbol matching begins because the generic selector parser treats every nonempty `x#y` as a file anchor.
  Evidence: `src/searchtools.rs::split_definition_selector` turns `Namespace.Type.#ctor` into anchor `Namespace.Type.` and lookup `ctor`.

- Observation: The repository already has the right canonical constructor identity and C# normalization hook.
  Evidence: explicit C# constructors are indexed as repeated owner/name selectors, and `src/analyzer/csharp/mod.rs::csharp_normalize_full_name` is used by exact definition lookup.

- Observation: Applying the constructor precedence to Scala would be unsafe even though Scala has a primary-constructor identity.
  Evidence: Scala permits ordinary same-named methods, so the final implementation limits the owner-name convention to Java, C#, and C++, where such a function declaration structurally denotes a constructor.

- Observation: The shared resolver and selector-routing changes did not regress the wider analyzer surface.
  Evidence: the complete default `cargo test` suite passed, including Java, C#, C++, Scala, file-anchor, usage graph, LSP, and persistence tests.

## Decision Log

- Decision: Treat the issues as related but not duplicate.
  Rationale: Both concern constructor selector semantics and share the lookup pipeline, but #627 is candidate precedence while #630 combines selector routing with a C# client alias.
  Date/Author: 2026-07-11 / Codex

- Decision: Preserve explicit constructor `CodeUnit`s and their canonical repeated-name selectors.
  Rationale: The source-round-trip policy in `.agents/docs/issue-581-synthetic-constructor-policy.md` intentionally keeps explicit constructors as ordinary source-backed functions. Removing or merging them would break explicit constructor lookup and usage analysis.
  Date/Author: 2026-07-11 / Codex

- Decision: Prefer a competing type over only its own same-named constructor for an ordinary bare-name lookup, using analyzer parent relationships and declaration kinds rather than source text.
  Rationale: This removes the false class/constructor ambiguity while retaining ambiguity between genuinely distinct types or unrelated same-named declarations. The rule belongs in shared resolution so all consumers see consistent semantics.
  Date/Author: 2026-07-11 / Codex

- Decision: Interpret terminal `.#ctor` only for C#, normalize it to the existing `Owner.Owner` identity, and continue treating real path-like `path#symbol` inputs as file anchors.
  Rationale: `#` must not become a universal member delimiter; an existing regression explicitly requires Java `A#method` to remain unsupported. C# full-name normalization is the established language-specific hook for client spellings.
  Date/Author: 2026-07-11 / Codex

## Outcomes & Retrospective

The implementation now resolves bare Java type names to the type when the only competing declaration is that type's explicit constructor, while preserving the repeated-name constructor selector and ambiguity between distinct same-named types. C# terminal `.#ctor` selectors now resolve explicit constructor overloads through the existing normalized identity, including within real file anchors, and classes without explicit constructors still return not found. No declaration extraction, synthetic-constructor policy, or source-text fallback changed. All focused checks, non-CUDA clippy, and the complete default test suite pass. Publication and issue closure remain.

## Context and Orientation

`CodeUnit` is Bifrost's indexed representation of a declaration. A Java or C# type is a class `CodeUnit`; an explicit constructor is a function `CodeUnit` whose canonical fully qualified name repeats the owner name, such as `pkg.Type.Type`. `src/analyzer/symbol_lookup.rs` resolves exact and fuzzy client inputs across analyzers. Fuzzy lookup considers fully qualified names, short names, and identifiers, which is why a bare `Type` currently sees both `pkg.Type` and `pkg.Type.Type`.

`src/searchtools.rs::resolve_selectable_definitions` converts symbol lookup results into either one selectable definition group, a not-found result, or an ambiguity containing exact selectors. `src/searchtools.rs::split_definition_selector` recognizes file-anchored selectors such as `src/a.ts#Widget`. Its current unconditional split conflicts with C#'s `.#ctor` spelling.

`src/analyzer/csharp/mod.rs::csharp_normalize_full_name` converts client and declaration names to the normalized keys used by exact C# definition lookup. It currently converts nested-type `$` separators to dots and is the appropriate place to convert a terminal `.#ctor` alias into the already-indexed repeated owner name.

The regression tests belong in `tests/searchtools_definition_selectors.rs` and/or `tests/searchtools_fuzzy_symbol_lookup.rs`. Both use `tests/common/inline_project.rs::InlineTestProject`, which builds small temporary projects from inline source files without bespoke filesystem setup.

## Plan of Work

First, add an inline Java project with a packaged class containing an explicit constructor. Assert that the bare type name returns the class source with no ambiguity, while the canonical repeated-name selector still returns the constructor body. Include a second-package same-name case if needed to prove that real type ambiguity remains.

Next, add an inline C# project with explicit constructor overloads. Assert that the fully qualified `Type.#ctor` selector resolves the same constructor definition group as `Type.Type`, that a type with no explicit constructor does not invent one, and that a genuine `.cs#symbol` file anchor continues to route as a file selector. Keep the existing Java `A#method` non-delimiter regression passing.

Implement bare-type precedence in the shared symbol resolver. When fuzzy candidates contain a class and a function whose analyzer parent is that same class and whose identifier equals the parent's identifier, discard that function candidate only for languages where constructors use the owner name. Apply the preference before deciding that multiple fully qualified candidates are ambiguous. Exact repeated-name constructor queries resolve before fuzzy precedence and therefore remain unchanged. Do not use signature text, regexes, or source scans.

Tighten file-anchor parsing so a terminal C# `.#ctor` input is left as a symbol name while path-like prefixes such as `Foo.cs#ctor` remain file anchors. Update C# full-name normalization to translate terminal `.#ctor` to the repeated final owner segment. Keep the alias C#-specific and avoid treating arbitrary hashes as member delimiters.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Add the focused tests, then run:

    cargo test --test searchtools_definition_selectors constructor -- --nocapture
    cargo test --test searchtools_fuzzy_symbol_lookup fuzzy_lookup_does_not_treat_arrow_or_hash_as_symbol_delimiters -- --nocapture

After implementation, rerun those tests and any directly affected analyzer unit tests. Then run:

    cargo fmt --check
    cargo clippy-no-cuda

Because this host has no `nvidia-smi` command and therefore no demonstrated CUDA toolchain, do not enable `--all-features`; the repository instructions require `cargo clippy-no-cuda` on non-CUDA machines.

Inspect the final scope with:

    git status --short
    git diff --check
    git diff -- src/analyzer/symbol_lookup.rs src/analyzer/csharp/mod.rs src/searchtools.rs tests/searchtools_definition_selectors.rs tests/searchtools_fuzzy_symbol_lookup.rs .agents/plans/constructor-selector-resolution-issues-627-630.md

Stage only changed files from this plan and commit them on the current `master` branch with a multiline message explaining the constructor-identity and selector-routing rationale.

## Validation and Acceptance

Acceptance requires observable end-to-end behavior through `get_symbol_sources`: a bare Java type with an explicit constructor returns exactly the class source and no ambiguity; its repeated-name selector returns the explicit constructor source; C# `Namespace.Type.#ctor` returns explicit constructor source under the canonical constructor label; a C# class without an explicit constructor returns not found for `#ctor`; two genuinely distinct same-named Java types remain ambiguous; and existing file-anchored selectors plus Java hash rejection remain unchanged.

The focused test binaries must pass. `cargo fmt --check`, `git diff --check`, and `cargo clippy-no-cuda` must complete without warnings or errors. If a broader test fails, determine whether it reveals an intended semantic update or a regression and update both implementation and this plan before committing.

## Idempotence and Recovery

All edits and test commands are safe to repeat. Inline test projects clean up their temporary roots automatically and semantic indexing stays disabled through `SearchToolsService::new_without_semantic_index`. Do not remove or overwrite the unrelated untracked `.agents/docs/` and `.brokk/` files present before this work. If a shared-resolver change causes unexpected cross-language behavior, keep the new tests and narrow the constructor-precedence predicate by language and structured parent kind rather than adding source-text exceptions.

## Artifacts and Notes

Issue #627 evidence:

    CompressionBodyRequestFilter
      -> org.zalando.nakadi.util.CompressionBodyRequestFilter
      -> org.zalando.nakadi.util.CompressionBodyRequestFilter.CompressionBodyRequestFilter

Issue #630 evidence:

    NzbDrone.Core.Organizer.FileNameBuilder.FileNameBuilder  -> constructor source
    NzbDrone.Core.Organizer.FileNameBuilder.#ctor           -> generic not_found

The first is a false fuzzy ambiguity; the second is an unrecognized alias plus selector-routing collision.

## Interfaces and Dependencies

No external dependencies or new public API are required. Reuse `IAnalyzer::parent_of`, `CodeUnit::{is_class,is_function,identifier,fq_name}`, `language_for_target`, `resolve_codeunit_fuzzy`, `split_definition_selector`, `looks_like_path_selector_anchor`, and `csharp_normalize_full_name`. The implementation must keep exact canonical constructor selectors and existing file-anchored selectors stable.

Plan revision note (2026-07-11): Created after validating both issues and reviewing the constructor source-round-trip policy. It records the shared design and the distinct fixes needed for candidate precedence and C# alias routing.

Plan revision note (2026-07-11 12:56Z): Updated after implementation and full validation. It records the deliberate exclusion of Scala, the exact regression coverage, and the remaining publish-and-close work requested by the user.
