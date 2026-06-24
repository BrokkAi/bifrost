# Go structural type hierarchy and shared type relations

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`. A future contributor should be able to start from this file alone, inspect the named source files, run the listed commands, and continue the work without needing earlier issue threads.

## Purpose / Big Picture

Go has declarations and usage analysis in Bifrost, but it currently does not provide LSP type hierarchy results because Go has no nominal class inheritance. The chosen product semantics for issue `#213` are that Go interface satisfaction is hierarchy-like: a concrete named type should appear as a descendant of each named interface whose method set it satisfies, and that interface should appear as a direct ancestor of the concrete type. This lets users ask the LSP type hierarchy for a Go interface and see implementers, or ask it for a concrete type and see the interfaces it structurally satisfies.

This work also introduces a shared internal relation model so non-nominal language facts are not forced into superclass ancestry. Ruby issue `#263` is the first proof: Ruby `include`, `prepend`, and `extend` must be modeled as typed mixin facts for method lookup, while only true superclass edges remain exposed through `TypeHierarchyProvider`.

## Progress

- [x] (2026-06-24T00:00Z) Created this ExecPlan from issue `#213`, issue `#263`, and the accepted broad semantic direction: Go exposes structural interface satisfaction as hierarchy-like, while Ruby mixins remain non-hierarchy relation facts.
- [x] (2026-06-24T00:00Z) Inspected Go tree-sitter node shapes for `interface_type`, `method_elem`, `type_elem`, `field_declaration`, `type_alias`, and `type_spec`.
- [x] (2026-06-24T00:00Z) Added `src/analyzer/type_relations.rs` with typed relation kinds, `TypeRelation`, `MethodKey`, and `MethodSet`, plus isolated method-set tests.
- [ ] Implement `src/analyzer/go/hierarchy.rs`, cache it from `GoMemoCaches`, and expose `GoAnalyzer::type_hierarchy_provider()`.
- [ ] Refactor Ruby declaration extraction so only true superclass facts feed `TypeHierarchyProvider`, and add a separate Ruby mixin relation collector for include/prepend/extend facts.
- [ ] Add focused Go hierarchy tests, Ruby hierarchy/mixin tests, capability parity coverage, and an LSP Go type hierarchy test.
- [ ] Run `cargo fmt --check`, focused tests, and `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Update GitHub issues `#213` and `#263` with the implemented design and validation notes. Create a follow-up issue only if one is needed.

## Surprises & Discoveries

- Observation: Go's tree-sitter grammar represents embedded interfaces and constraint/type-set terms as `type_elem` children of `interface_type`.
  Evidence: Initial structured discovery inspected Go AST shapes before helper signatures were finalized. The implementation milestone must add tests proving embedded-interface and type-set behavior.

- Observation: Ruby mixins currently enter type hierarchy through raw supertypes.
  Evidence: The Ruby repair milestone must separate superclass facts from `include`, `prepend`, and `extend` facts, then update the hierarchy tests so mixins are no longer reported as ancestors.

- Observation: Go empty interfaces need an explicit bounded policy.
  Evidence: The Go implementation milestone must prove named empty interfaces are supported without expanding `interface{}` / `any` to every named type in the workspace.

## Decision Log

- Decision: Keep `TypeHierarchyProvider` as the public LSP-facing projection and add richer type-relation facts underneath it.
  Rationale: The current provider API already matches LSP hierarchy requests. Go wants structural satisfaction projected as hierarchy, while Ruby mixins explicitly must not be projected as hierarchy.
  Date/Author: 2026-06-24 / Codex

- Decision: Implement the broad Go v1 semantics, including receiver-aware method sets, embedded structs and interfaces, aliases, generic constraints, and a bounded policy for `any` / empty interfaces.
  Rationale: The accepted plan chose broad semantics. Correctness still requires structured tree-sitter/analyzer facts; no name-only guesses or regex fallbacks are allowed.
  Date/Author: 2026-06-24 / Codex

- Decision: Reuse existing Go package/import/type-reference helpers where possible instead of creating a separate resolver path.
  Rationale: Go usage analysis already has structured package resolution and type-reference extraction. Duplicating it would risk drift between usage and hierarchy behavior.
  Date/Author: 2026-06-24 / Codex

## Outcomes & Retrospective

Milestone 1 outcome: the ExecPlan exists, and the shared type-relation vocabulary is available behind a crate-internal module. The public `TypeHierarchyProvider` trait is unchanged. Go and Ruby behavior changes remain pending in later milestones.

## Context and Orientation

`src/analyzer/capabilities.rs` defines `TypeHierarchyProvider`, the trait used by LSP type hierarchy requests. The trait returns direct ancestors and descendants for a `CodeUnit`, which is Bifrost's representation of a declaration such as a class, type, module, method, or field.

`src/lsp/handlers/type_hierarchy.rs` asks the active analyzer for a `TypeHierarchyProvider`. If no provider exists, or if `supports_type_hierarchy` returns false for a code unit, the LSP request returns `null`. This file should not need semantic special cases for Go or Ruby; each language should expose the right provider projection.

`src/analyzer/go/mod.rs` wraps the Go `TreeSitterAnalyzer`. Go named types are currently represented as `CodeUnitType::Class`, Go methods are child functions under their receiver type, Go struct fields are child fields, and Go type aliases are module fields marked through `TypeAliasProvider`. `resources/treesitter/go/definitions.scm` captures named types, methods, struct fields, and interface methods, while `src/analyzer/go/declarations.rs` contains the structured declaration walker.

`src/analyzer/usages/go_graph` contains existing package/import/type-reference machinery. This implementation should reuse its structured helpers where possible or move small helpers to a shared Go module when hierarchy code needs them. It must not add string-splitting path parsers where tree-sitter nodes or existing resolver helpers can provide the structure.

`src/analyzer/ruby/hierarchy.rs` currently resolves raw supertypes from the generic analyzer state. PR `#262` put Ruby `include`, `prepend`, and `extend` into that same raw-supertype path, which issue `#263` says is wrong. Ruby superclass edges should remain in `TypeHierarchyProvider`; mixin facts should be stored separately for future method lookup.

## Plan of Work

Milestone 1: shared plan and relation vocabulary. Add this ExecPlan and a shared internal module for type relations and method sets. The module should define relation kinds for nominal inheritance, structural satisfaction, embedding, trait implementation, and Ruby mixin include/prepend/extend. It should also provide method keys based on method name plus an opaque language-owned signature string, and a helper that checks whether one method set satisfies another through a language-specific compatibility callback. Acceptance: `cargo test type_relations --lib` and a library clippy check pass for this checkpoint.

Milestone 2: Go structural hierarchy. Implement Go hierarchy indexing. The index should parse each Go file using tree-sitter, resolve package-qualified and same-package type references through existing Go package/import rules, collect named interface method requirements, collect named concrete type method sets, add promoted methods from embedded structs, add embedded interface requirements, and connect concrete types to interfaces when the concrete method set satisfies the interface method set. Type aliases should resolve to their target type for satisfaction checks. The empty interface and `any` should be accepted as interfaces, but subtype expansion must be bounded so `interface{}` does not return every type in a large workspace. Acceptance: focused Go hierarchy tests, capability parity, and the Go LSP hierarchy test pass.

Milestone 2 also exposes this through `GoAnalyzer::type_hierarchy_provider()`. Direct ancestors of a concrete type are the interfaces it satisfies. Direct descendants of an interface are the concrete named types that satisfy it, subject to the empty-interface cap. `supports_type_hierarchy` should return true for Go named types and named interfaces that the hierarchy index understands, and false for aliases or other declarations that cannot produce stable hierarchy items.

Milestone 3: Ruby mixin separation. Repair Ruby mixin handling. Update Ruby declaration extraction or hierarchy resolution so raw superclass facts and mixin facts are separate. `TypeHierarchyProvider` for Ruby should resolve only true superclass edges. Mixin facts should be represented in the shared relation model with include/prepend/extend kinds, and focused tests should prove those facts distinguish instance lookup from singleton/class lookup even though they are not hierarchy ancestors. Acceptance: Ruby hierarchy tests and isolated Ruby mixin relation tests pass.

Milestone 4: closeout and issue updates. Update GitHub issues. Add a comment to `#213` documenting the chosen and implemented Go semantics. Add a comment to `#263` documenting that Ruby mixins now use the shared relation model and remain outside type hierarchy. Create a follow-up issue only if structured inspection shows a broad Go feature cannot be implemented safely in this PR. Acceptance: full focused test set, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` pass, and this ExecPlan records final validation evidence.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/4609/bifrost`.

Before implementation, sync the branch:

    git fetch && git rebase

The branch was already up to date at plan creation.

During implementation, run focused tests after each milestone. Useful commands include:

    cargo test type_relations --lib
    cargo test mixin_relations_distinguish_include_prepend_and_extend --lib
    cargo test --test go_type_hierarchy_test
    cargo test --test ruby_type_hierarchy_test
    cargo test --test analyzer_capability_parity
    cargo test --test bifrost_lsp_server bifrost_lsp_server_go_type_hierarchy_returns_structural_interface_edges
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Older draft command names that were superseded during implementation were:

    cargo test go_type_hierarchy
    cargo test ruby_type_hierarchy
    cargo test bifrost_lsp_server::go

Milestone 1 validation passed with `cargo test type_relations --lib`. Later commands are listed for their corresponding milestones and must be recorded when those milestones land.

## Validation and Acceptance

The Go acceptance tests must prove that a concrete type satisfying a named interface appears as a direct descendant of that interface and that the interface appears as a direct ancestor of the concrete type. They must include value receivers, pointer receivers, embedded interface requirements, promoted methods from embedded structs where structurally resolvable, aliases, generic constraints, incompatible same-name signatures, and the empty-interface cap.

The Ruby acceptance tests must prove that superclass ancestors still appear, while `include`, `prepend`, and `extend` modules do not appear as direct ancestors. Separate tests must prove the mixin facts are still collected and distinguish instance lookup from singleton/class lookup.

The LSP acceptance tests must prove that Go `textDocument/prepareTypeHierarchy`, `typeHierarchy/supertypes`, and `typeHierarchy/subtypes` return hierarchy items for supported Go types, and that unsupported or capped cases return stable null or bounded results. Mixed-language routing must continue to return null for unsupported delegates.

Before completion, run:

    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings

Validation evidence from Milestone 1 on 2026-06-24:

    cargo test type_relations --lib
    result: 2 passed

## Idempotence and Recovery

All code changes are additive or narrow refactors and can be retried safely. If a hierarchy index attempt produces false positives, keep the failing negative test and narrow the structured resolver rather than adding a fallback. If a broad Go semantic cannot be represented from tree-sitter nodes or existing analyzer facts, do not guess; document the exact unsupported construct in this plan and create a follow-up issue with the failed test scenario.

If Ruby refactoring exposes missing usage/get-definition support, keep this issue scoped to separating mixin facts from hierarchy. The shared relation model should store enough data for future method lookup, but full Ruby usage graph work belongs to the existing Ruby epic.

## Artifacts and Notes

Important issue context:

    #213: Go currently lacks TypeHierarchyProvider. The accepted decision is that structural interface satisfaction is hierarchy-like for Go.
    #263: Ruby mixins must be separated from type hierarchy because include, prepend, and extend affect different lookup paths.

## Interfaces and Dependencies

Add a shared internal module under `src/analyzer`, for example `src/analyzer/type_relations.rs`, and export it only inside the crate unless tests require `pub(crate)` visibility. Define relation and method-set types with stable names so Go and Ruby can share them:

    pub(crate) enum TypeRelationKind {
        NominalInheritance,
        StructuralSatisfaction,
        Embedding,
        TraitImplementation,
        MixinInclude,
        MixinPrepend,
        MixinExtend,
    }

    pub(crate) struct TypeRelation {
        pub from: CodeUnit,
        pub to: CodeUnit,
        pub kind: TypeRelationKind,
    }

    pub(crate) struct MethodKey {
        pub name: String,
        pub signature: Option<String>,
    }

    pub(crate) struct MethodSet {
        pub methods: HashSet<MethodKey>,
    }

Names may be adjusted during implementation if the final code is clearer, but the semantic boundary must remain: relation facts are richer than the LSP hierarchy projection.

Revision note 2026-06-24 / Codex: Initial ExecPlan created before code edits. It records the accepted cross-cutting design, broad Go v1 scope, Ruby `#263` relation to the work, and validation gates.

Revision note 2026-06-24 / Codex: Updated after Milestone 1 review so the checkpoint only claims the ExecPlan and shared relation vocabulary. Later implementation and validation notes must be added by the milestones that actually introduce those changes.
