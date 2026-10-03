//! Language capability registry.
//!
//! Framework code (code that serves every language) reaches per-language behavior
//! through [`language_support`] instead of naming a language module or matching on
//! `Language` itself. The match below is exhaustive with no wildcard arm, so adding a
//! `Language` variant fails to compile until it is registered.
//!
//! [`LanguageSupport`] grows one method per capability as
//! `.agents/plans/analysis-language-registry-spi.md` converts each dispatch list.
//! Methods land with the milestone that consumes them, so this surface is deliberately
//! smaller than the plan's eventual one.

use crate::analyzer::common::language_for_target;
use crate::analyzer::loop_facts::LoopSyntax;
use crate::analyzer::semantic::ProcedureKind;
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, ExactExternalCallProof,
};
use crate::analyzer::usages::get_type::TypeLookupOutcome;
use crate::analyzer::usages::inverted_edges::{
    JsTsScopedUsageEdges, UsageEdgeWeights, UsageEdges, UsageNodeKey,
};
use crate::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverFacts, ReceiverFileCtx, ReceiverFileFacts, ReceiverFileSetup,
};
use crate::analyzer::usages::reference_site::{ResolvedReferenceSite, node_range};
use crate::analyzer::usages::workspace_graph::UsageEcosystem;
use crate::analyzer::usages::{GraphUsageAnalyzer, UsageAnalyzer};
use crate::analyzer::{
    BoundedDefinitionLookup, CodeUnit, ForwardQueryProvider, IAnalyzer, Language, ParserFlavor,
    ProjectFile, Range, SignatureMetadata, cpp, csharp, go, java, js_ts, kotlin, php, python, ruby,
    rust, scala, structural,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::fq_name::{
    FqName, SegmentKind, joined_segments, segment_interner,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use std::any::Any;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalDeclarationVisibility {
    Lexical,
    Hoisted,
}

/// Interpret one already-extracted package spelling through the registered
/// language separator and preserve path packages as path segments.
pub(crate) fn package_fq_name(language: Language, package: &str) -> FqName {
    let separator = language_support(language)
        .expect("every indexed language has registered support")
        .package_separator();
    let kind = if language == Language::Go {
        SegmentKind::Path
    } else {
        SegmentKind::Package
    };
    let interner = segment_interner();
    let mut name = FqName::new();
    for segment in joined_segments(package, separator) {
        name.push(interner.intern(segment, kind));
    }
    name
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LocalDeclarationBindingScope<'tree> {
    pub scope: tree_sitter::Node<'tree>,
    pub visibility: LocalDeclarationVisibility,
}

/// Physical source roles used by navigation after language-owned interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeclarationNavigationRole {
    Declaration,
    Definition,
    Both,
    Unknown,
}

impl DeclarationNavigationRole {
    pub(crate) fn api_label(self) -> Option<&'static str> {
        match self {
            Self::Declaration => Some("declaration"),
            Self::Definition => Some("definition"),
            Self::Both | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct DeclarationNavigationOccurrence {
    pub range: Range,
    pub role: DeclarationNavigationRole,
}
/// AST-level helper that returns the identifier introduced by one pattern node.
pub(crate) type PatternBindingNameProvider =
    for<'tree> fn(tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>>;

/// Syntax roles one language supplies for procedure-local source proofs:
/// statement-entry assessment and loop repetition. Both enumerate syntax
/// independently of the producer, so a statement or loop classified here
/// without matching producer evidence stays open.
#[derive(Clone, Copy)]
pub(crate) struct ProcedureSyntaxRoles {
    /// Classify an executable statement node; `None` for any other node.
    pub statement_kind: fn(tree_sitter::Node<'_>) -> Option<&'static str>,
    /// Classify a conditional loop whose repetition the loop proof can join
    /// to control flow. Iteration loops (for-each) are not classified.
    pub loop_site: for<'tree> fn(tree_sitter::Node<'tree>) -> Option<LoopSyntax<'tree>>,
    /// Whether `node` is the syntax of a procedure of this kind.
    pub procedure_matches: fn(ProcedureKind, tree_sitter::Node<'_>) -> bool,
    /// Whether `node` starts code that belongs to another procedure.
    pub nested_procedure: fn(tree_sitter::Node<'_>) -> bool,
}

pub(crate) trait LanguageSupport: Send + Sync {
    /// The `Language` variant this support serves. Must equal the registry match key.
    fn language(&self) -> Language;

    /// The syntax roles procedure-local source proofs need for this language.
    /// `None` means the language's lowering does not author statement entries.
    fn procedure_syntax_roles(&self) -> Option<ProcedureSyntaxRoles> {
        None
    }

    /// The AST-level helper for extracting one pattern node's binding identifier.
    /// Shared analysis uses this for pattern bindings the generic lexical environment
    /// does not model.
    fn pattern_binding_name_provider(&self) -> Option<PatternBindingNameProvider> {
        None
    }

    /// The module represented by the file itself, when this language has one.
    /// Use the same constructor as the storage adapter's path module projection.
    /// Such a module has no declaration token and navigates to file start;
    /// source-declared modules use their ordinary declaration name ranges.
    fn path_synthetic_module_unit(&self, _file: &ProjectFile) -> Option<CodeUnit> {
        None
    }

    /// The name universe this language's declarations belong to.
    ///
    /// The single owner of ecosystem knowledge: [`UsageEcosystem::of`] delegates here,
    /// and the edge-pass collector derives a pass's ecosystem from the supports that
    /// own it rather than asking the pass. A pass shared by several languages (JS/TS)
    /// requires those languages to agree here, which [`edge_passes`] asserts.
    fn ecosystem(&self) -> UsageEcosystem;

    /// Return this language's own answer to "which files can hold a reference
    /// to `target`", seeded from `seed_files`. `None` leaves the framework's
    /// generic importer walk in charge; `Some` is complete for this language
    /// and replaces that walk.
    ///
    /// A language may narrow its reverse-import closure by any admission test
    /// it can prove from structure -- a file the closure reaches but whose
    /// syntax cannot spell `target` holds no reference to it, proven or
    /// unproven -- so the answer stays complete while the framework's file
    /// budget sees a set it can admit whole.
    fn referencing_candidate_files(
        &self,
        _analyzer: &dyn IAnalyzer,
        _target: &CodeUnit,
        _seed_files: &BTreeSet<ProjectFile>,
        _cancellation: Option<&CancellationToken>,
    ) -> Option<HashSet<ProjectFile>> {
        None
    }

    /// The one reference-analysis plugin serving both target-directed and
    /// whole-workspace workloads for this language.
    fn reference_plugin(&self) -> ReferenceLanguagePlugin;

    fn call_relation_provider(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_relations::CallRelationProvider> {
        None
    }

    /// Refine proof for resolved source-call targets using language-owned
    /// receiver evidence. The default keeps the resolver's proof unchanged.
    fn refine_resolved_call_targets(
        &self,
        _analyzer: &dyn IAnalyzer,
        _token: QueryToken<'_>,
        _file: &ProjectFile,
        _site: &ExternalCalleeSite<'_>,
        _targets: &mut [crate::analyzer::usages::call_relations::CallDispatchTarget],
    ) {
    }

    fn rename_provider(&self) -> Option<&'static dyn crate::symbol_rename::RenameProvider> {
        None
    }

    /// The builder of this language's whole-workspace selected inverse
    /// reference index, or `None` when the language has no selected resolution
    /// engine and its inverse edges are derived one declaration at a time.
    ///
    /// Registering a provider makes the selected index this language's only
    /// inverse-edge authority for RQL `edges_of` and the policy edge asserts,
    /// so those consumers report a build refusal as an incomplete inverse
    /// axis rather than deriving the same question by the other route.
    fn selected_inverse_reference_provider(
        &self,
    ) -> Option<
        &'static dyn crate::analyzer::structural::reference_edges::SelectedInverseReferenceProvider,
    > {
        None
    }

    /// This language's reader of the macro rows its producer sealed into a
    /// selected blob, or `None` when the language publishes no macro rows.
    ///
    /// Selected resolution replays macro invocations from persisted rows, and
    /// the rows belong to the producing language, so the operation asks the
    /// mount's support for this reader instead of calling a language module's
    /// storage directly.
    fn selected_macro_source_rows(
        &self,
    ) -> Option<&'static dyn crate::analyzer::store::resolution_operation::SelectedMacroSourceRows>
    {
        None
    }

    /// This language's analyzer inside `analyzer`, viewed as a forward-query provider.
    /// Each support owns the downcast to its own concrete analyzer; `None` means the
    /// workspace does not analyze this language, which callers treat as an empty result
    /// rather than a failure.
    fn forward_query_provider<'a>(
        &self,
        analyzer: &'a dyn IAnalyzer,
    ) -> Option<&'a dyn ForwardQueryProvider>;

    /// Language-owned producer for resolver-proven actual-to-formal call
    /// conversion facts. The shared call-conversion relation supplies the
    /// exact call/signature/actual/formal join and invokes this capability for
    /// owner applicability and AST-backed type proof.
    fn call_argument_conversion_prover(
        &self,
    ) -> Option<&'static dyn crate::analyzer::usages::call_conversion::CallArgumentConversionProver>
    {
        None
    }

    /// Whether this language's saved callable-default metadata is complete and
    /// closed for the analyzer generation. `None` leaves default-argument
    /// binding unproven because the language has no such capability or the
    /// analyzer is absent, or the metadata scan is incomplete.
    fn saved_default_arguments_available(&self, _analyzer: &dyn IAnalyzer) -> Option<bool> {
        None
    }

    /// Signature metadata this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. `None` means the workspace does not analyze this language, or the
    /// language keeps no signature metadata at all: Java, JavaScript and TypeScript
    /// answer `None` because their analyzers expose no such projection, and the receiver
    /// query charges both cases to the same budget limit.
    fn signature_metadata_limited(
        &self,
        _analyzer: &dyn IAnalyzer,
        _unit: &CodeUnit,
        _limit: usize,
    ) -> Option<LimitedQueryRows<SignatureMetadata>> {
        None
    }

    /// Whether `spelling`, read in `file`, resolves through this language's
    /// external declaration surface to a member proven both static and a
    /// compile-time constant (#2538).
    ///
    /// The workspace oracle uses this to discharge a `FieldMemory` gap for a
    /// read of an external constant: such a read cannot observe or produce a
    /// heap effect the gap would otherwise have to keep open. The default is
    /// `false` -- a language without a modeled external declaration surface,
    /// or whose analyzer is absent from this workspace, leaves the gap
    /// standing. An implementation must answer `true` only from proven
    /// declaration evidence, never from the spelling's shape.
    fn external_compile_time_constant_member(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _spelling: &str,
    ) -> bool {
        false
    }

    /// Whether the call whose source mapping spans `call` in `source` provably
    /// cannot throw an exception the catch parameter whose name spans
    /// `catch_parameter` catches.
    ///
    /// The workspace oracle uses this to drop a lowered catch binding from
    /// that call's thrown value, so the parameter keeps the origins of the
    /// throws that can reach it. The default is `false`, which keeps every
    /// binding. An implementation must answer `true` only from the language's
    /// own exception typing rules, never from spelling.
    fn call_cannot_reach_catch_parameter(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _source: &Arc<str>,
        _call: std::ops::Range<usize>,
        _catch_parameter: std::ops::Range<usize>,
    ) -> bool {
        false
    }

    /// Rendered signatures this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. `None` means the workspace does not analyze this language, or the
    /// language keeps no direct signature projection.
    fn signatures_limited(
        &self,
        _analyzer: &dyn IAnalyzer,
        _unit: &CodeUnit,
        _limit: usize,
    ) -> Option<LimitedQueryRows<String>> {
        None
    }

    /// Declaration ranges this language's analyzer holds for `unit`, visiting at most
    /// `limit` rows. No default: every registered language answers this, and a silent
    /// `None` would report every receiver in that language as budget-exceeded.
    fn declaration_ranges_limited(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
        limit: usize,
    ) -> Option<LimitedQueryRows<Range>>;

    /// Canonical physical occurrences for navigation. Missing required evidence is
    /// `None`; languages without distinct physical roles expose unknown roles.
    fn declaration_navigation_occurrences(
        &self,
        analyzer: &dyn IAnalyzer,
        unit: &CodeUnit,
    ) -> Option<Vec<DeclarationNavigationOccurrence>> {
        Some(
            analyzer
                .ranges(unit)
                .into_iter()
                .map(|range| DeclarationNavigationOccurrence {
                    range,
                    role: DeclarationNavigationRole::Unknown,
                })
                .collect(),
        )
    }

    /// Separator between a package name and its parent. Only Go and C++ differ from the
    /// dotted default.
    fn package_separator(&self) -> &'static str {
        "."
    }

    /// The separator this language writes between the segments of a qualified callee
    /// path *in source*: `java.net.URLDecoder.decode` against `std::str::from_utf8`.
    /// Rust (#2596) and C++ (#2606) write `::`; every other language keeps the dotted
    /// default.
    ///
    /// This decides only how the spelling is cut. The canonical owner published from
    /// it is always dot-joined, because that is how authored procedure-summary symbols
    /// are indexed; see
    /// [`crate::analyzer::semantic::split_canonical_qualified_callee`].
    fn qualified_call_separator(&self) -> &'static str {
        "."
    }

    /// How dead-code analysis proves this language's candidates.
    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport::default()
    }

    /// Whether a candidate requires the language's precise dead-code strategy.
    fn dead_code_needs_precise_scan(
        &self,
        _analyzer: &dyn IAnalyzer,
        _candidate: &CodeUnit,
    ) -> bool {
        false
    }

    /// Bounded structural receiver resolution, or `None` when receiver queries for this
    /// language take another route (Java runs a resolution session, JS/TS runs its own
    /// syntax-index path) or are unsupported entirely.
    ///
    /// This is the single owner of the structural-receiver capability: the receiver query
    /// gate admits exactly the languages that answer `Some` here, so an absent resolver
    /// yields the `receiver_analysis_language_unsupported` report rather than reaching a
    /// dispatch that cannot serve it.
    ///
    /// `get_type_by_location` dispatches through the same resolver (with its own, more
    /// generous budget), so one bounded core answers both the receiver query and the
    /// interactive type lookup; Java and JS/TS take their other routes there too.
    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// The native row-backed point resolver of a language whose production
    /// routing has not flipped yet, reached only by the rollout probes. At the
    /// flip it becomes the language's `structural_receiver` and this returns
    /// `None` again.
    #[cfg(any(test, feature = "test-support"))]
    fn native_rollout_points(&self) -> Option<&'static dyn StructuralReceiverResolver> {
        None
    }

    /// Whether a workspace-relative path is a build configuration input this
    /// language captures by exact bytes (for example go.mod or a Gradle build
    /// file), for the selected configuration and its overlay guards.
    fn is_configuration_input_path(&self, _path: &std::path::Path) -> bool {
        false
    }

    /// Class-set type-propagation adapter for this language, or `None` when the
    /// engine has no per-language facts for it. The default means class-set
    /// propagation reports `Unsupported` for this language: an absent adapter
    /// is an honest capability statement, never an empty class set.
    fn type_flow_adapter(&self) -> Option<&'static dyn crate::analyzer::semantic::TypeFlowAdapter> {
        None
    }

    /// Per-file setup and per-query factory for languages whose receiver analysis runs on
    /// their own syntax index instead of through [`StructuralReceiverResolver`].
    ///
    /// One accessor to a two-method trait rather than two capabilities, for the reason
    /// [`StructuralReceiverResolver`] is one trait: a language answering only half of it
    /// would strand the query between preparing a file and querying it.
    fn receiver_facts(&self) -> Option<&'static dyn ReceiverFactsFactory> {
        None
    }

    /// Candidate files this language contributes to a usage query beyond the generic
    /// import-graph and text-search routes. Consulted for default discovery and incomplete
    /// seed providers; a complete execution-scope provider is never augmented.
    fn candidate_augmentation(&self, _ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        None
    }

    /// Expand a source-level callee spelling to the external identity that semantic
    /// models publish, when this language can prove the expansion from structured
    /// language evidence. The default offers no expansion.
    ///
    /// The call site's parsed file and exact source are handed over for the same
    /// reason [`Self::single_segment_external_owner`] receives them: a language
    /// may have to ask a scope question about the evidence it expands from --
    /// Rust's import binder expands only while the path it binds has a root the
    /// workspace does not claim (#3484).
    fn expand_imported_external_callee(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        _callee_text: &str,
        _site: Option<&ExternalCalleeSite<'_>>,
    ) -> Option<ImportedExternalCallee> {
        None
    }

    /// Whether this language's external surface is reached through owners that
    /// carry only one segment (#2598).
    ///
    /// The dot in `java.net.URLDecoder.decode` is the proxy the unmaterialized
    /// external route was born with: an owner that already spells its own
    /// qualification needs no import or type resolution to name an identity.
    /// That proxy holds for Java and Rust and fails outright for JavaScript and
    /// TypeScript, whose entire standard surface is `JSON.parse`,
    /// `Buffer.from`, `crypto.randomUUID` and `path.join` -- every one of them
    /// a single segment.
    ///
    /// Saying `true` here does not admit every single-segment owner. It states
    /// that such an owner *can* be an identity in this language, so the
    /// classification stage consults
    /// [`Self::single_segment_external_owner`] to decide each one.
    fn publishes_single_segment_external_owners(&self) -> bool {
        false
    }

    /// The canonical owner a single-segment external callee publishes, or
    /// `None` when this owner names no external identity at all (#2598).
    ///
    /// Called only when [`Self::publishes_single_segment_external_owners`] is
    /// true and only after the callee has already failed to resolve, so the
    /// question is never "what does this name mean" but "does anything in this
    /// file already answer that". A language answers it from its own binding
    /// structure; there is no shared rule, because what may legally shadow a
    /// runtime global differs by language.
    ///
    /// Returning a *different* owner than `owner` is how a module binding
    /// publishes its module's identity rather than the local name a file
    /// happened to give it.
    ///
    /// `member` is the callee's own member name. An owner that is a shared
    /// mutable object publishes an identity for one member at a time, because
    /// the file may have replaced exactly that member (#3427).
    fn single_segment_external_owner(
        &self,
        _owner: &str,
        _member: &str,
        _site: &ExternalCalleeSite<'_>,
    ) -> Option<String> {
        None
    }

    /// How a fully qualified name is spelled for a reader. The default is the indexed
    /// spelling itself; the three languages that override strip indexer-only decoration
    /// their users never type (Scala's object `$`, C#'s generic arity and `global::`
    /// prefix, TypeScript's `$static` static-member marker).
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol.to_string()
    }

    /// The decoration [`Self::display_symbol_name`] removes, expressed as a change to
    /// the *structured* name instead of an edit to its rendering. `None` when `fq`
    /// carries no decoration for this language to remove, which is the common case and
    /// costs the caller nothing.
    ///
    /// A rendering cannot answer this question. [`FqName::render_native`] appends
    /// exactly one `$` for each [`SegmentKind::Companion`] segment, and a Scala object's
    /// own name may end in `$` too -- `object ConstellationNode$` is legal Scala and
    /// Constellation-Labs/constellation writes it -- so the rendered name ends in two
    /// `$`, one decoration and one the source wrote. Reading that string back with
    /// `trim_end_matches('$')` removed both and printed
    /// `org.constellation.ConstellationNode`, a spelling no declaration answers (#3505).
    /// Changing a segment's *kind* leaves every segment's text intact, so only the
    /// renderer's own suffix disappears.
    fn undecorated_fq_name(&self, _fq: &FqName) -> Option<FqName> {
        None
    }

    /// How a declaration's identifier is written at its declaration site, which is what
    /// range selection has to match against source text. Same decoration as
    /// [`Self::display_symbol_name`] removes, applied to a single identifier.
    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier
    }

    /// An additional spelling of one symbol-path segment that a query may reasonably use.
    /// The default offers no alternative; C# offers the arity-free form, because indexed
    /// generic names carry `` Type`1 `` and nobody types the arity (#1063).
    fn alias_name_segment<'s>(&self, segment: &'s str) -> &'s str {
        segment
    }

    /// The source range of the identifier `node` carries. The default is the node's own
    /// span; Ruby narrows it, because its symbol literals include a leading `:` or
    /// surrounding quotes that are not part of the name.
    fn declaration_name_range(&self, node: tree_sitter::Node<'_>, _source: &str) -> Range {
        node_range(node)
    }

    /// The identifier a symbol-literal node names, or `None` when the node is not one.
    /// Only Ruby has a literal form whose text differs from the name it denotes.
    fn symbol_literal_name(&self, _node: tree_sitter::Node<'_>, _source: &str) -> Option<String> {
        None
    }

    /// The callee of a call whose grammar names it positionally rather than by field, or
    /// `None` when the generic field lookup already finds it.
    fn call_callee_node<'t>(&self, _call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The identifier a declaration names, for languages whose grammar names it
    /// positionally rather than by field, or `None` when the field lookup or
    /// document-order search already finds it.
    fn declaration_name_node<'t>(
        &self,
        _declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The argument-list nodes of a call whose grammar nests them out of reach of the
    /// generic field and child-kind lookup. `Some` replaces that lookup entirely, so an
    /// empty vector means "this call has no arguments", not "look elsewhere".
    fn call_argument_nodes<'t>(
        &self,
        _call: tree_sitter::Node<'t>,
    ) -> Option<Vec<tree_sitter::Node<'t>>> {
        None
    }

    /// The identifier naming the callee of a factory call, for languages whose call shape
    /// the framework's per-grammar table cannot express through field lookups alone.
    fn factory_name_node<'t>(&self, _call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// The default expression of a formal parameter whose grammar does not
    /// expose that expression through a named field. `None` leaves the shared
    /// named-field lookup in charge.
    fn positional_parameter_default<'t>(
        &self,
        _parameter: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        None
    }

    /// Whether a lexical definition may be resolved from the focused node at all. Rust
    /// says no for struct-field names, whose owning type -- not the enclosing scope --
    /// decides what they denote, so resolving them lexically would answer with the wrong
    /// binding rather than with none.
    fn focus_resolves_lexically(&self, _focus: tree_sitter::Node<'_>) -> bool {
        true
    }

    /// Whether `node`, already recognized as a local declaration by node kind, is one this
    /// language's grammar produces where no local binding exists. C++ says yes for an
    /// `init_declarator` inside a recovered exported class body, where the parse shape of a
    /// member declaration is indistinguishable from a local one.
    fn skips_local_declaration(&self, _node: tree_sitter::Node<'_>, _source: &str) -> bool {
        false
    }

    /// The syntax scope that owns a local declaration whose binding rules differ from
    /// ordinary source-order visibility. `None` keeps the framework's default rule that
    /// a local declaration is visible only after its declaration. JavaScript and
    /// TypeScript return their structured variable-binding scope and state whether the
    /// binding is lexical or hoisted.
    fn local_declaration_binding_scope<'tree>(
        &self,
        _node: tree_sitter::Node<'tree>,
    ) -> Option<LocalDeclarationBindingScope<'tree>> {
        None
    }

    /// Whether the lexical resolver must traverse syntax after the focused byte to find
    /// declarations that bind earlier source positions. A declaration found there is
    /// still accepted only when [`Self::local_declaration_binding_scope`] proves that the
    /// current syntax scope owns it.
    fn scans_local_declarations_after_focus(&self) -> bool {
        false
    }

    /// Attach language-owned source scope to declarations emitted by semantic-model rules.
    /// The default leaves generated symbols unchanged.
    fn bind_generated_symbols(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _symbols: &mut [crate::analyzer::semantic_model::SemanticModelSymbol],
    ) {
    }

    /// This language's tree-sitter grammar for `flavor`. The parameter exists for
    /// TypeScript, whose `.ts` and `.tsx` files parse under distinct grammars while
    /// sharing one adapter; every other language answers the same grammar for both.
    fn parser_language(&self, flavor: ParserFlavor) -> tree_sitter::Language;

    /// This language's normalized structural-search adapter, the spec `query_code` runs
    /// against.
    fn structural_spec(&self) -> &'static dyn structural::StructuralSpec;

    /// This language's tree-sitter highlights query, or `None` when it ships none.
    /// Every registered language currently answers `Some`; the option is here so a
    /// future one can be analyzable without shipping highlights instead of returning an
    /// empty query that silently produces no captures.
    fn highlight_query(&self) -> Option<&'static str>;
}

/// Identity of one whole-workspace edge resolver family.
///
/// Not one per `Language`: JavaScript and TypeScript are served by a single resolver and
/// report the same id, while Java, Scala and Kotlin run three distinct resolvers over one
/// shared candidate space. Framework collectors deduplicate by this id, so neither fact
/// has to be re-encoded at a consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EdgePassId {
    Rust,
    Python,
    JsTs,
    Java,
    Scala,
    Kotlin,
    Go,
    CSharp,
    Cpp,
    Php,
    Ruby,
}

impl EdgePassId {
    /// Every pass, in the order framework collectors run them.
    ///
    /// Passes sharing an ecosystem are adjacent, which is load-bearing: the workspace
    /// graph reports the ecosystems it resolved by pushing one entry per pass and
    /// collapsing *consecutive* duplicates, so splitting the JVM trio apart would report
    /// `Jvm` three times.
    pub(crate) const ALL: [Self; 11] = [
        Self::Rust,
        Self::Python,
        Self::JsTs,
        Self::Java,
        Self::Scala,
        Self::Kotlin,
        Self::Go,
        Self::CSharp,
        Self::Cpp,
        Self::Php,
        Self::Ruby,
    ];

    /// Profiling-scope suffix naming this pass.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Python => "python",
            Self::JsTs => "jsts",
            Self::Java => "java",
            Self::Scala => "scala",
            Self::Kotlin => "kotlin",
            Self::Go => "go",
            Self::CSharp => "csharp",
            Self::Cpp => "cpp",
            Self::Php => "php",
            Self::Ruby => "ruby",
        }
    }
}

/// One language family's whole-workspace `caller -> callee` scan.
///
/// Replaces the per-language `UsageEdgeResolver` uniformity contract, which had eleven
/// monomorphic implementations and no polymorphic use. What that trait documented and
/// this one enforces: every graph language builds its edges in a single inverted pass
/// over the workspace, borrowing its concrete analyzer once, rather than scanning each
/// symbol's candidate files.
///
/// The two methods are two *finalizations* of the same underlying scan, not two scans.
/// `edge_sites` keeps every call site's path and line; `edge_weights` keeps reference-kind
/// counts. Neither is reconstructible from the other, and each consumer calls only the one
/// it needs, so a language still scans exactly once per consumer.
pub(crate) trait LanguageEdgePass: Send + Sync {
    fn id(&self) -> EdgePassId;

    /// Check input authority even when unavailable declarations leave no roots.
    /// None means no known failure (including an inapplicable language).
    ///
    /// `request_files` is the file set this request will resolve: the files a
    /// rooted request named, or every analyzable file when it named none. A
    /// pass whose authority is per file must answer about those files only, so
    /// a rooted request is never made unavailable by a file it never named and
    /// never pays a workspace-sized read for one.
    fn input_failure(
        &self,
        _analyzer: &dyn IAnalyzer,
        _request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        None
    }

    /// Whether an FQN-only edge can be a proven relation to a logical callable
    /// family even when no single physical overload is selected. Consumers
    /// retain every candidate endpoint and report the non-exact relation.
    fn permits_logical_family_targets(&self) -> bool {
        false
    }

    /// Location-bearing edges for the `usage_graph` consumer. `None` when the workspace
    /// does not analyze this pass's languages; the consumer records nothing and reports
    /// no diagnostic. An applicable pass that could not build reports `Unavailable`.
    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites>;

    /// Reference-kind counts for the workspace-graph consumer, in whichever node
    /// identity this pass keys by.
    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights>;
}

/// One language family's semantic hooks behind [`ReferenceEngine`](crate::analyzer::usages::ReferenceEngine).
///
/// Planning, admission, traversal, cancellation, completeness and canonical
/// row formatting belong to the engine. This descriptor is deliberately only
/// the semantic plug point. Keeping the target resolver and file scanner in
/// one registered value prevents the two workloads from being wired through
/// unrelated registry paths again.
#[derive(Clone, Copy)]
pub(crate) struct ReferenceLanguagePlugin {
    strategy: &'static dyn GraphUsageAnalyzer,
    graph: LanguageGraphBackend,
}

impl ReferenceLanguagePlugin {
    pub(crate) const fn new(
        strategy: &'static dyn GraphUsageAnalyzer,
        edge_pass: &'static dyn LanguageEdgePass,
    ) -> Self {
        Self {
            strategy,
            graph: LanguageGraphBackend::Legacy(edge_pass),
        }
    }

    pub(crate) const fn native(
        strategy: &'static dyn GraphUsageAnalyzer,
        provider: &'static dyn NativeWorkspaceGraphProvider,
    ) -> Self {
        Self {
            strategy,
            graph: LanguageGraphBackend::Native(provider),
        }
    }

    pub(crate) const fn target_strategy(self) -> &'static dyn GraphUsageAnalyzer {
        self.strategy
    }
}

/// A pass has exactly one graph authority. Native endpoints retain declaration
/// identity instead of being converted back into legacy name-based edges.
#[derive(Clone, Copy)]
pub(crate) enum LanguageGraphBackend {
    Legacy(&'static dyn LanguageEdgePass),
    Native(&'static dyn NativeWorkspaceGraphProvider),
}

impl LanguageGraphBackend {
    fn id(self) -> EdgePassId {
        match self {
            Self::Legacy(pass) => pass.id(),
            Self::Native(provider) => provider.id(),
        }
    }

    /// The input-authority preflight of whichever backend holds this pass.
    ///
    /// Both graph consumers run this before building a catalog, because an
    /// unavailable declaration catalog is empty rather than absent: without the
    /// preflight a pass whose canonical facts could not be read reports a
    /// complete graph with no edges. The question is the backend's, not the
    /// legacy implementation's, so it is asked through the authority the
    /// language actually registered.
    pub(crate) fn input_failure(
        self,
        analyzer: &dyn IAnalyzer,
        request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        match self {
            Self::Legacy(pass) => pass.input_failure(analyzer, request_files),
            Self::Native(provider) => provider.input_failure(analyzer, request_files),
        }
    }
}

pub(crate) trait NativeWorkspaceGraphProvider: Send + Sync {
    fn id(&self) -> EdgePassId;

    /// Check input authority even when unavailable declarations leave no roots.
    /// None means no known failure (including an inapplicable language).
    ///
    /// `request_files` carries the same contract as
    /// [`LanguageEdgePass::input_failure`]: it is the request's own file set,
    /// and a per-file authority answers about those files alone.
    fn input_failure(
        &self,
        _analyzer: &dyn IAnalyzer,
        _request_files: &[ProjectFile],
    ) -> Option<LanguageEdgeFailure> {
        None
    }

    /// An empty caller slice admits no sources. Dependency definitions remain
    /// available, but only admitted callers may contribute outgoing edges.
    fn project(
        &self,
        analyzer: &dyn IAnalyzer,
        admitted_callers: &[ProjectFile],
        cancellation: &CancellationToken,
    ) -> crate::analyzer::store::Result<
        crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome,
    >;
}

/// Location-bearing edges in the node identity native to the language family.
/// Package-scoped languages use an FQN; module-scoped JS/TS retains the source
/// file so same-named exports never collapse at the plugin boundary.
pub(crate) enum LanguageEdgeSites {
    Fqn(UsageEdges),
    Scoped(UsageEdges<UsageNodeKey>),
    Unavailable(LanguageEdgeFailure),
}

/// An applicable language pass could not obtain complete input facts. This is
/// different from an inapplicable pass or a complete graph with no edges.
#[derive(Debug)]
pub(crate) struct LanguageEdgeFailure {
    pub reason: &'static str,
    pub files: Vec<ProjectFile>,
}

/// Reference-kind counts in this pass's node identity. JS/TS keys by `{file, fqn}` because
/// same-named exports in different modules are different declarations; every other pass
/// keys by fqn within its ecosystem.
pub(crate) enum LanguageEdgeWeights {
    Fqn(UsageEdgeWeights),
    Scoped(JsTsScopedUsageEdges),
    Unavailable(LanguageEdgeFailure),
}

/// Inputs to a sites scan. `keep_file` drops out-of-scope caller files before parsing and
/// is called once per file, never per reference.
pub(crate) struct EdgeSiteScanCtx<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) fqns: &'a HashSet<String>,
    pub(crate) scoped_callers: &'a HashSet<UsageNodeKey>,
    pub(crate) keep_file: &'a (dyn Fn(&ProjectFile) -> bool + Sync),
}

/// Inputs to a weights scan. Both node sets are supplied because the collector cannot know
/// which identity a pass keys by; a pass reads exactly one of them.
pub(crate) struct EdgeWeightScanCtx<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) fqns: &'a HashSet<String>,
    pub(crate) scoped_nodes: &'a HashSet<UsageNodeKey>,
    pub(crate) keep_file: &'a (dyn Fn(&ProjectFile) -> bool + Sync),
}

/// One pass together with the ecosystem its owning supports agree on.
pub(crate) struct EdgePassEntry {
    pub(crate) id: EdgePassId,
    pub(crate) ecosystem: UsageEcosystem,
    pub(crate) languages: Vec<Language>,
    pub(crate) backend: LanguageGraphBackend,
}

/// The graph authority every edge pass is registered with, as one digest.
///
/// Which implementation answers a language's reference, call, graph and
/// dead-code questions is an engine input exactly like the grammar it parses
/// with: two engines that disagree about it derive different answers from
/// identical bytes. Every identity that must not survive a per-language flip --
/// the workspace usage-graph cache key and the analysis epoch a recorded read
/// set carries -- folds this value, so a flip rotates them all and there is no
/// separate hand-bumped version to remember on the next one.
///
/// Derived from the live registry rather than from a constant, which is why
/// [`graph_authority_digest_of`] takes the passes: the production digest reads
/// [`edge_passes`], and a test can ask what the same registry would digest with
/// one language on the other authority.
pub(crate) fn graph_authority_digest() -> StableDigest {
    static PRODUCTION: std::sync::OnceLock<StableDigest> = std::sync::OnceLock::new();
    *PRODUCTION.get_or_init(|| graph_authority_digest_of(&edge_passes()))
}

pub(crate) fn graph_authority_digest_of(passes: &[EdgePassEntry]) -> StableDigest {
    let mut hasher = CanonicalHasher::new(GRAPH_AUTHORITY_DOMAIN);
    for entry in passes {
        hasher.field(
            entry.id.as_str(),
            match entry.backend {
                LanguageGraphBackend::Legacy(_) => b"legacy".as_slice(),
                LanguageGraphBackend::Native(_) => b"native".as_slice(),
            },
        );
    }
    StableDigest::from_array(hasher.finish())
}

/// Domain for [`graph_authority_digest`].
const GRAPH_AUTHORITY_DOMAIN: &[u8] = b"bifrost-language-graph-authority:v1";

/// Every distinct edge pass, deduplicated by [`EdgePassId`] and ordered by
/// [`EdgePassId::ALL`].
///
/// The shared half of both edge consumers: iterating supports directly would run the
/// JS/TS pass twice, and deduplicating by ecosystem would collapse the three JVM passes
/// into one. Ecosystem selection, node-set choice and result conversion stay with each
/// consumer, because those are where the two genuinely differ.
pub(crate) fn edge_passes() -> Vec<EdgePassEntry> {
    let mut entries = Vec::with_capacity(EdgePassId::ALL.len());
    for id in EdgePassId::ALL {
        let mut entry: Option<EdgePassEntry> = None;
        for language in Language::ANALYZABLE {
            let support = language_support(language).expect("analyzable languages are registered");
            let backend = support.reference_plugin().graph;
            if backend.id() != id {
                continue;
            }
            match &mut entry {
                None => {
                    entry = Some(EdgePassEntry {
                        id,
                        ecosystem: support.ecosystem(),
                        languages: vec![language],
                        backend,
                    });
                }
                Some(entry) => {
                    assert_eq!(
                        entry.ecosystem,
                        support.ecosystem(),
                        "{language:?} shares edge pass {id:?} but disagrees on its ecosystem"
                    );
                    assert!(
                        matches!(
                            (entry.backend, backend),
                            (
                                LanguageGraphBackend::Legacy(_),
                                LanguageGraphBackend::Legacy(_)
                            ) | (
                                LanguageGraphBackend::Native(_),
                                LanguageGraphBackend::Native(_)
                            )
                        ),
                        "languages sharing a pass must share its graph authority"
                    );
                    entry.languages.push(language);
                }
            }
        }
        entries.push(entry.unwrap_or_else(|| panic!("no language owns edge pass {id:?}")));
    }
    entries
}

/// How dead-code analysis proves one language's candidates.
///
/// Two proofs, and a language may offer either, both, or neither. `strategy` is the
/// precise per-symbol scan; `bulk` is a whole-workspace edge build a bucket of candidates
/// is proven against at once. Absence is not "unimplemented" and is deliberately silent:
/// Python and C++ have no per-symbol strategy because their candidates are always proven
/// in bulk, and a candidate that reaches a path its language does not serve is skipped as
/// inconclusive.
#[derive(Clone, Copy, Default)]
pub(crate) struct DeadCodeSupport {
    pub(crate) strategy: Option<&'static dyn UsageAnalyzer>,
    pub(crate) bulk: Option<&'static dyn DeadCodeBulkProof>,
}

/// One language family's whole-workspace dead-code proof.
///
/// Deliberately not [`LanguageEdgePass`]. The dead-code builds diverge from the general
/// passes in ways a shared contract could only express as mode flags: Python resolves a
/// bounded target set through its cached builder, Scala uses its full builder with no file
/// predicate, Rust checks analyzer availability and measures its file cap off the
/// analyzer's own file list, and JS/TS needs per-node seed statuses the general weights
/// product does not carry. Each divergence stays inside the implementation that owns it.
pub(crate) trait DeadCodeBulkProof: Send + Sync {
    /// Resolver-family identity, the same partition the edge passes use: candidates of
    /// languages served by one proof (JavaScript and TypeScript) share a bucket, while
    /// the JVM trio keep three.
    fn id(&self) -> EdgePassId;

    /// Whether `candidate` must take the per-symbol precise path instead of this proof.
    fn needs_precise_scan(&self, routing: DeadCodeRouting<'_>) -> bool;

    /// Whether a precise candidate may take the conservative report-local inbound
    /// preflight. This is restricted to a language whose precise overload scan
    /// cannot complete within the report budget and whose inbound graph is used
    /// only to establish inconclusive evidence. Other precise-path reasons and
    /// languages stay on their precise route.
    fn supports_precise_inbound_preflight(&self, _routing: DeadCodeRouting<'_>) -> bool {
        false
    }

    /// Whole-workspace facts this proof memoizes across the candidates of one report.
    /// The default serves proofs whose routing decision needs none.
    fn new_memo(&self) -> Box<dyn Any + Send> {
        Box::new(())
    }

    /// The file count and label this proof's cap diagnostics report, or the reason the
    /// proof cannot run at all.
    fn preflight(&self, analyzer: &dyn IAnalyzer) -> DeadCodeBulkPreflight;

    /// Resolve inbound edges for `candidates` over every declaration of this proof's
    /// languages as a possible caller.
    fn build(&self, analyzer: &dyn IAnalyzer, candidates: &[CodeUnit])
    -> Option<DeadCodeBulkEdges>;
}

pub(crate) struct DeadCodeRouting<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) candidate: &'a CodeUnit,
    pub(crate) file_cap: usize,
    /// The value [`DeadCodeBulkProof::new_memo`] produced for this bucket.
    pub(crate) memo: &'a mut dyn Any,
}

pub(crate) enum DeadCodeBulkPreflight {
    /// Ready to build. `label` names the language family in cap diagnostics ("C++",
    /// "JS/TS"), and `files` is the count the cap is measured against, which is not
    /// always the project's analyzable-file count for one `Language`.
    Ready { label: &'static str, files: usize },
    /// The proof cannot run; every bucketed candidate is skipped with this reason.
    Unavailable(&'static str),
}

pub(crate) enum DeadCodeBulkEdges {
    /// `Arc` rather than a bare value because Python's and Scala's builders hand back
    /// analyzer-cached graphs that outlive one report.
    Fqn(Arc<UsageEdges>),
    Scoped(JsTsScopedUsageEdges),
}

/// Every non-synthetic declaration of `language` that `is_caller` admits, plus the
/// candidates themselves. Bulk proofs need the whole workspace as possible callers while
/// resolving only their bounded candidate set, so the two sets differ.
pub(crate) fn fqn_bulk_nodes(
    analyzer: &dyn IAnalyzer,
    language: Language,
    is_caller: impl Fn(&CodeUnit) -> bool,
    candidates: &[CodeUnit],
) -> HashSet<String> {
    let mut nodes: HashSet<String> = analyzer
        .all_declarations()
        .filter(|unit| {
            language_for_target(unit) == language && !unit.is_synthetic() && is_caller(unit)
        })
        .map(|unit| unit.fq_name())
        .collect();
    nodes.extend(candidates.iter().map(CodeUnit::fq_name));
    nodes
}

pub(crate) fn candidate_fqns(candidates: &[CodeUnit]) -> HashSet<String> {
    candidates.iter().map(CodeUnit::fq_name).collect()
}

pub(crate) fn analyzable_file_count(analyzer: &dyn IAnalyzer, language: Language) -> usize {
    analyzer
        .project()
        .analyzable_files(language)
        .map_or(0, |files| files.len())
}

/// Fq names declared more than once as a function in `language`. An overloaded name is
/// ambiguous to an fqn-keyed bulk proof, so the languages that can overload consult this
/// before admitting a candidate.
pub(crate) fn overloaded_function_fqns(
    analyzer: &dyn IAnalyzer,
    language: Language,
) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::default();
    for declaration in analyzer.all_declarations().filter(|unit| {
        language_for_target(unit) == language && !unit.is_synthetic() && unit.is_function()
    }) {
        *counts.entry(declaration.fq_name()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter_map(|(fqn, count)| (count > 1).then_some(fqn))
        .collect()
}

/// Whether one exact FQN has multiple non-synthetic function definitions in `language`.
///
/// Unlike [`overloaded_function_fqns`], this is candidate-local: the definition index is
/// queried for the requested name instead of scanning every declaration in the workspace.
/// That distinction matters when an FQN-keyed bulk graph is used to decide whether a
/// precise overload scan is required.
pub(crate) fn fqn_has_multiple_function_definitions(
    analyzer: &dyn IAnalyzer,
    language: Language,
    fqn: &str,
) -> bool {
    analyzer
        .get_definitions(fqn)
        .into_iter()
        .filter(|definition| {
            language_for_target(definition) == language
                && !definition.is_synthetic()
                && definition.is_function()
        })
        .take(2)
        .count()
        > 1
}

/// The pair of bounded resolvers a structural receiver query needs. One trait rather than
/// two independent capabilities: a language that can answer one and not the other would
/// leave the receiver query with half an implementation part-way through a report.
pub(crate) trait StructuralReceiverResolver: Send + Sync {
    fn resolve_type_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<TypeLookupOutcome>;

    fn resolve_definition_bounded(
        &self,
        query: BoundedReceiverQuery<'_>,
    ) -> BoundedResolution<DefinitionLookupOutcome>;
}

#[derive(Clone, Copy)]
pub(crate) struct BoundedReceiverQuery<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) file: &'a ProjectFile,
    pub(crate) source: &'a str,
    pub(crate) tree: Option<&'a tree_sitter::Tree>,
    pub(crate) site: &'a ResolvedReferenceSite,
    pub(crate) budget: ReceiverAnalysisBudget,
    pub(crate) cancellation: Option<&'a CancellationToken>,
}

/// Everything a per-query receiver-facts provider borrows. `'tree` is the prepared tree's
/// lifetime and `'a` the query's; both outlive the boxed provider.
///
/// This context and [`ReceiverFactsFactory`] stayed behind when the rest of the
/// receiver-facts vocabulary lowered to `brokk-bifrost-core`: `analyzer` is a full
/// `IAnalyzer` because the only implementer's provider hands it to
/// `get_definition::js_ts`'s candidate resolvers, which downcast through
/// `resolve_analyzer` (`cached_jsts_index`) and read `IAnalyzer::type_alias_provider`.
/// Narrowing it to `CodeUnitIndex` needs those resolvers relocated first.
pub(crate) struct ReceiverFactContext<'a, 'tree> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) definitions: &'a dyn BoundedDefinitionLookup,
    pub(crate) language: Language,
    pub(crate) file: &'a ProjectFile,
    pub(crate) source: &'a str,
    pub(crate) root: tree_sitter::Node<'tree>,
    pub(crate) facts: &'a ReceiverFileFacts,
}

/// A language's own receiver analysis, resolving against a syntax index it builds rather
/// than against structural facts. JS/TS is the only implementer today.
pub(crate) trait ReceiverFactsFactory: Send + Sync {
    fn prepare_file(&self, ctx: &ReceiverFileCtx<'_>) -> ReceiverFileSetup;

    /// One provider per bounded resolution query, never per node: it owns query-local
    /// caches, so its allocation is amortized over every node the query resolves.
    fn make_receiver_facts<'a, 'tree: 'a>(
        &self,
        ctx: ReceiverFactContext<'a, 'tree>,
    ) -> Box<dyn ReceiverFacts<'tree> + 'a>;
}

pub(crate) struct CandidateCtx<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) target: &'a CodeUnit,
    pub(crate) cancellation: &'a CancellationToken,
}

/// The file-scoped evidence [`LanguageSupport::single_segment_external_owner`]
/// may consult about one call site (#2598).
///
/// The classification stage already parsed the file to find the call, so the
/// tree and the exact source it was parsed from are handed over rather than
/// re-derived. `callee_start_byte` is the offset of the callee reference
/// itself, which is what a lexically scoped binding question has to be asked
/// at: the same name can be a parameter in one body and a free global three
/// lines later.
pub(crate) struct ExternalCalleeSite<'a> {
    pub(crate) source: &'a str,
    pub(crate) tree: &'a tree_sitter::Tree,
    pub(crate) callee_start_byte: usize,
    /// File-wide evidence shared by every callee site classified in this file.
    pub(crate) file_evidence: &'a ExternalCalleeFileEvidence,
}

/// What [`LanguageSupport::expand_imported_external_callee`] proved about one
/// imported callee spelling.
///
/// The published text and the structured evidence are two spellings of one
/// callee, not two independent facts. A language that only expanded a spelling
/// publishes [`Self::text`]. A language whose resolver selected the callable
/// itself publishes [`Self::proven`], and the exact call proof and the
/// owner/member identity then travel together to the call boundary: a summary
/// is behavior attached to a callable, so text alone must not stand for the
/// declaration the summary describes (#3484).
pub(crate) struct ImportedExternalCallee {
    /// The canonical callee text the boundary publishes, written with the
    /// language's own separator.
    pub(crate) canonical_callee: String,
    /// The exact declaration-side proof of the selected callable and its
    /// written call shape.
    pub(crate) exact_external_call: Option<ExactExternalCallProof>,
    /// The resolver-owned owner/member identity that exact proof names.
    pub(crate) external_callee_identity:
        Option<crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity>,
}

impl ImportedExternalCallee {
    /// An expansion whose language proved the callee text but no exact
    /// declaration-side call shape.
    pub(crate) fn text(canonical_callee: impl Into<String>) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            exact_external_call: None,
            external_callee_identity: None,
        }
    }

    /// An expansion whose language selected the callable itself. The proof and
    /// the identity are two spellings of what it selected, so they are stored
    /// and published together.
    pub(crate) fn proven(
        proof: ExactExternalCallProof,
        identity: crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity,
    ) -> Self {
        Self {
            canonical_callee: proof.canonical_callee().to_owned(),
            exact_external_call: Some(proof),
            external_callee_identity: Some(identity),
        }
    }
}

/// The file-wide proofs [`LanguageSupport::single_segment_external_owner`]
/// reuses across one file's callee sites.
///
/// An owner rule can need evidence that walks the whole file: JavaScript must
/// prove the file writes nothing to the member it is about to publish (#3427).
/// Classification runs once per unresolved callee, so a file with many external
/// member calls would otherwise rewalk itself once per call. One value is built
/// per file and handed to each of its sites.
#[derive(Default)]
pub(crate) struct ExternalCalleeFileEvidence {
    pub(crate) js_ts_module_member_writes: js_ts::JsTsModuleMemberWriteMemo,
}

/// Extra candidate files for one query target, split by how the query's budgets treat them.
///
/// The split is behavior, not bookkeeping. `protected` joins the candidate set before the
/// finder takes its protected snapshot, so both the file-count and the source-byte budget
/// admit those files ahead of everything else. `supplemental` joins after the snapshot and
/// is therefore what either budget drops first -- which is what PHP's composer expansion
/// needs, since a single autoload-visible target pulls in every analyzed PHP file and would
/// otherwise displace the import-graph candidates that are far likelier to hold a usage.
#[derive(Default)]
pub(crate) struct CandidateAugmentation {
    pub(crate) protected: HashSet<ProjectFile>,
    pub(crate) supplemental: HashSet<ProjectFile>,
}

impl CandidateAugmentation {
    pub(crate) fn protected(files: HashSet<ProjectFile>) -> Self {
        Self {
            protected: files,
            supplemental: HashSet::default(),
        }
    }

    pub(crate) fn supplemental(files: HashSet<ProjectFile>) -> Self {
        Self {
            protected: HashSet::default(),
            supplemental: files,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.supplemental.is_empty()
    }
}

/// What `target`'s language adds to the default candidate route, or `None` when it adds
/// nothing.
///
/// A cancelled token skips the augmentation and leaves the query holding what it has
/// already accumulated: whether to abandon the query is the caller's decision, taken at the
/// cancellation check it runs next, and the two callers differ on it.
pub(crate) fn candidate_augmentation(ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
    if ctx.cancellation.is_cancelled() {
        return None;
    }
    let augmentation =
        language_support(language_for_target(ctx.target))?.candidate_augmentation(ctx)?;
    (!augmentation.is_empty()).then_some(augmentation)
}

/// The languages whose adapters adopt workspace files that no extension list
/// claims, by resolving their own sources' imports (#1837).
///
/// CLAIMS SEAM. This registry is the single-claimant premise every other part
/// of include-driven inference rests on: `storage_language_key_for_file` hands
/// the unclaimed-extension storage-key namespace to the asking adapter, and
/// `MultiAnalyzer::dispatch_language` routes an unclaimed-extension file to the
/// one language named here. Both are sound only while this list holds at most
/// one entry. Adding a second language means implementing the drop-and-report
/// rule stated on [`crate::analyzer::LanguageAdapter::infer_claimed_files`]:
/// a file two languages claim belongs to neither, and a diagnostic must name
/// both claimants.
pub(crate) fn claim_inferring_languages() -> &'static [Language] {
    const LANGUAGES: &[Language] = &[Language::Cpp];
    debug_assert!(
        LANGUAGES.len() <= 1,
        "include-driven claim inference has no multi-claimant resolution yet, but the registry \
         lists {LANGUAGES:?}"
    );
    LANGUAGES
}

pub(crate) fn language_support(language: Language) -> Option<&'static dyn LanguageSupport> {
    let support: Option<&'static dyn LanguageSupport> = match language {
        Language::None => None,
        Language::Java => Some(&java::JavaSupport),
        Language::Go => Some(&go::GoSupport),
        Language::Cpp => Some(&cpp::CppSupport),
        Language::JavaScript => Some(&js_ts::JavascriptSupport),
        Language::TypeScript => Some(&js_ts::TypescriptSupport),
        Language::Python => Some(&python::PythonSupport),
        Language::Rust => Some(&rust::RustSupport),
        Language::Php => Some(&php::PhpSupport),
        Language::Scala => Some(&scala::ScalaSupport),
        Language::CSharp => Some(&csharp::CSharpSupport),
        Language::Ruby => Some(&ruby::RubySupport),
        Language::Kotlin => Some(&kotlin::KotlinSupport),
    };
    debug_assert!(
        support.is_none_or(|support| support.language() == language),
        "registry arm for {language:?} is served by a support reporting {:?}",
        support.map(LanguageSupport::language)
    );
    support
}

/// Every build ecosystem that can derive project topology (#2448), in a stable
/// order.
///
/// Assembly, like `language_support` above: a provider knows one build model
/// and nothing outside its own module dispatches over build ecosystems. The
/// registry is keyed by ecosystem rather than by [`Language`] because one
/// build model serves several languages -- Java, Kotlin, and Scala share the
/// Maven reactor -- and because a workspace can carry build metadata for a
/// language it has no sources in yet.
pub(crate) fn build_model_providers()
-> &'static [&'static dyn crate::analyzer::topology::BuildModelProvider] {
    const PROVIDERS: &[&dyn crate::analyzer::topology::BuildModelProvider] =
        &[&crate::analyzer::jvm::topology::JVM_BUILD_MODEL];
    PROVIDERS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
    use crate::analyzer::{
        CSharpAnalyzer, CppAnalyzer, FileSetProject, GoAnalyzer, JavaAnalyzer, JavascriptAnalyzer,
        KotlinAnalyzer, PhpAnalyzer, PythonAnalyzer, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer,
        TypescriptAnalyzer,
    };
    use brokk_bifrost_core::analyzer::common::INCLUDE_CLAIMING_LANGUAGE;
    use std::collections::{BTreeMap, BTreeSet};

    const ANALYZABLE: [Language; 12] = [
        Language::Java,
        Language::Go,
        Language::Cpp,
        Language::JavaScript,
        Language::TypeScript,
        Language::Python,
        Language::Rust,
        Language::Php,
        Language::Scala,
        Language::CSharp,
        Language::Ruby,
        Language::Kotlin,
    ];

    fn support_of(language: Language) -> &'static dyn LanguageSupport {
        language_support(language).unwrap_or_else(|| panic!("{language:?} must be registered"))
    }

    fn languages_reporting(capability: impl Fn(&dyn LanguageSupport) -> bool) -> Vec<Language> {
        ANALYZABLE
            .into_iter()
            .filter(|language| capability(support_of(*language)))
            .collect()
    }

    /// Every observable capability of every registered language, as one reviewed table.
    ///
    /// Centralized defaults keep an absent capability silent by design -- that is the whole
    /// point of the trait's defaults -- so this snapshot is what makes the silence visible:
    /// a capability appearing or disappearing arrives as a diff here instead of as a change
    /// in behavior nobody looked at. It is also the single source of truth the capability
    /// documentation matrix renders from.
    ///
    /// Absences the table records rather than merely permits, each a real user-visible
    /// behavior: C++ and Python have no per-symbol dead-code strategy because their
    /// candidates are always proven in bulk; Kotlin now uses a bulk proof for classes and
    /// callable declarations while fields and duplicate-FQN functions stay precise; Java and
    /// JS/TS answer no structural
    /// receiver because their receiver analysis runs another route entirely (a resolution
    /// session, and the JS/TS syntax index reached through `facts`).
    ///
    /// There is no type-lookup column: `get_type_by_location` dispatches through the
    /// same bounded receiver contract this table's `recv` column records, with Java and
    /// JS/TS served by the same other routes `recv`/`facts` name, so every registered
    /// language answers it and a separate column would restate those three.
    ///
    /// Deliberately observable-only. Behind `dyn` there is no way to distinguish an
    /// inherited default from an identical override, and a hand-maintained
    /// implemented-versus-default table would recreate the parallel capability list this
    /// refactor exists to delete. Three capabilities are therefore absent here rather than
    /// forgotten, because none answers anything without a built workspace:
    /// `candidate_augmentation` needs an analyzer and a target, and
    /// `signature_metadata_limited`, `signatures_limited`, and
    /// `declaration_ranges_limited` need an analyzer and a `CodeUnit`. Each is pinned by its
    /// own behavior test instead.
    const CAPABILITY_MATRIX: &str = "\
language   | ecosystem            | pass   | graph  | sep | strategy | bulk   | recv | facts | hl  | tflow
Java       | Jvm                  | Java   | legacy | .   | yes      | Java   | -    | -     | yes | -
Go         | Go                   | Go     | legacy | /   | yes      | Go     | yes  | -     | yes | -
Cpp        | Cpp                  | Cpp    | legacy | ::  | -        | Cpp    | yes  | -     | yes | -
JavaScript | JavaScriptTypeScript | JsTs   | legacy | .   | yes      | JsTs   | -    | yes   | yes | yes
TypeScript | JavaScriptTypeScript | JsTs   | legacy | .   | yes      | JsTs   | -    | yes   | yes | yes
Python     | Python               | Python | legacy | .   | -        | Python | yes  | -     | yes | yes
Rust       | Rust                 | Rust   | native | .   | yes      | Rust   | yes  | -     | yes | -
Php        | Php                  | Php    | legacy | .   | yes      | Php    | yes  | -     | yes | yes
Scala      | Jvm                  | Scala  | legacy | .   | yes      | Scala  | yes  | -     | yes | -
CSharp     | CSharp               | CSharp | legacy | .   | yes      | CSharp | yes  | -     | yes | -
Ruby       | Ruby                 | Ruby   | legacy | .   | yes      | Ruby   | yes  | -     | yes | yes
Kotlin     | Jvm                  | Kotlin | legacy | .   | yes      | Kotlin | yes  | -     | yes | -
";

    fn mark(present: bool) -> &'static str {
        if present { "yes" } else { "-" }
    }

    fn capability_matrix() -> String {
        let mut rendered = String::from(
            "language   | ecosystem            | pass   | graph  | sep | strategy | bulk   | recv | facts | hl  | tflow\n",
        );
        for language in ANALYZABLE {
            let support = support_of(language);
            let dead_code = support.dead_code();
            let backend = support.reference_plugin().graph;
            let backend_name = match backend {
                LanguageGraphBackend::Legacy(_) => "legacy",
                LanguageGraphBackend::Native(_) => "native",
            };
            let bulk = match backend {
                LanguageGraphBackend::Native(provider) => Some(provider.id()),
                LanguageGraphBackend::Legacy(_) => dead_code.bulk.map(|bulk| bulk.id()),
            };
            rendered.push_str(&format!(
                "{:<10} | {:<20} | {:<6} | {:<6} | {:<3} | {:<8} | {:<6} | {:<4} | {:<5} | {:<3} | {}\n",
                format!("{language:?}"),
                format!("{:?}", support.ecosystem()),
                format!("{:?}", backend.id()),
                backend_name,
                support.package_separator(),
                mark(dead_code.strategy.is_some()),
                bulk.map_or_else(|| "-".to_string(), |bulk| format!("{bulk:?}")),
                mark(support.structural_receiver().is_some()),
                mark(support.receiver_facts().is_some()),
                mark(support.highlight_query().is_some()),
                mark(support.type_flow_adapter().is_some()),
            ));
        }
        rendered
    }

    #[test]
    fn the_capability_matrix_matches_its_snapshot() {
        assert_eq!(capability_matrix(), CAPABILITY_MATRIX);
    }

    /// Flipping one language's graph authority must move the digest that every
    /// cross-engine identity folds.
    ///
    /// The workspace usage-graph cache key and the analysis epoch a recorded
    /// read set carries both fold `graph_authority_digest`. Before it existed,
    /// the only thing separating a pre-flip identity from a post-flip one was a
    /// hand-bumped representation constant, so a derived artifact built by the
    /// legacy Rust resolver and one built by the native engine shared an id
    /// whenever the bytes were equal.
    #[test]
    fn the_graph_authority_digest_separates_a_flipped_language_from_production() {
        struct StandInLegacyPass(EdgePassId);
        impl LanguageEdgePass for StandInLegacyPass {
            fn id(&self) -> EdgePassId {
                self.0
            }

            fn edge_sites(&self, _ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites> {
                unimplemented!("the authority digest reads registration, never a scan")
            }

            fn edge_weights(&self, _ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights> {
                unimplemented!("the authority digest reads registration, never a scan")
            }
        }
        static RUST_LEGACY_STAND_IN: StandInLegacyPass = StandInLegacyPass(EdgePassId::Rust);

        let production = edge_passes();
        assert!(
            matches!(
                production
                    .iter()
                    .find(|entry| entry.id == EdgePassId::Rust)
                    .expect("Rust owns an edge pass")
                    .backend,
                LanguageGraphBackend::Native(_)
            ),
            "Rust is registered on the native graph authority"
        );
        assert_eq!(
            graph_authority_digest_of(&production),
            graph_authority_digest(),
            "the production digest is the digest of the production registry"
        );

        let flipped: Vec<EdgePassEntry> = production
            .into_iter()
            .map(|entry| EdgePassEntry {
                backend: if entry.id == EdgePassId::Rust {
                    LanguageGraphBackend::Legacy(&RUST_LEGACY_STAND_IN)
                } else {
                    entry.backend
                },
                ..entry
            })
            .collect();
        assert_ne!(
            graph_authority_digest_of(&flipped),
            graph_authority_digest(),
            "one language on the other authority is a different engine"
        );
    }

    /// Compiler exhaustiveness proves every `Language` has an arm; it cannot prove the
    /// arm is wired to the matching support.
    #[test]
    fn every_analyzable_language_resolves_to_its_own_support() {
        for language in ANALYZABLE {
            assert_eq!(support_of(language).language(), language);
        }
        assert!(language_support(Language::None).is_none());
    }

    #[test]
    fn call_conversion_producers_are_registered_only_by_their_owners() {
        for language in ANALYZABLE {
            let registered = support_of(language)
                .call_argument_conversion_prover()
                .is_some();
            assert_eq!(
                registered,
                matches!(
                    language,
                    Language::Java | Language::TypeScript | Language::Rust | Language::Scala
                ),
                "call conversion capability registration for {language:?}"
            );
        }
    }

    /// The receiver query gate admits exactly the languages reporting this capability,
    /// so widening or narrowing the set silently changes which files answer receiver
    /// queries at all and which get `receiver_analysis_language_unsupported`.
    #[test]
    fn exactly_nine_languages_report_a_structural_receiver_resolver() {
        assert_eq!(
            languages_reporting(|support| support.structural_receiver().is_some()),
            vec![
                Language::Go,
                Language::Cpp,
                Language::Python,
                Language::Rust,
                Language::Php,
                Language::Scala,
                Language::CSharp,
                Language::Ruby,
                Language::Kotlin,
            ]
        );
    }

    /// The receiver query admits a language through exactly two capabilities, and JS/TS is
    /// the only one served by this second route. A language reporting neither gets
    /// `receiver_analysis_language_unsupported`; Java is the one that reports neither and
    /// is still served, through its own resolution session.
    #[test]
    fn only_js_and_ts_report_their_own_receiver_facts() {
        assert_eq!(
            languages_reporting(|support| support.receiver_facts().is_some()),
            vec![Language::JavaScript, Language::TypeScript]
        );
        for language in ANALYZABLE {
            let support = support_of(language);
            assert!(
                support.structural_receiver().is_none() || support.receiver_facts().is_none(),
                "{language:?} claims both receiver routes"
            );
        }
    }

    fn edge_pass_id_of(language: Language) -> EdgePassId {
        support_of(language).reference_plugin().graph.id()
    }

    /// Pass cardinality is the whole reason [`EdgePassId`] exists: it is neither one per
    /// language nor one per ecosystem, and getting it wrong is silent. Collapsing the JVM
    /// trio would drop two of the three resolvers; splitting JS/TS would run one scan
    /// twice and double every JS/TS edge weight.
    #[test]
    fn passes_are_shared_by_dialect_and_split_by_resolver() {
        assert_eq!(
            edge_pass_id_of(Language::JavaScript),
            edge_pass_id_of(Language::TypeScript),
            "JavaScript and TypeScript are served by one pass"
        );
        let jvm = [Language::Java, Language::Scala, Language::Kotlin].map(edge_pass_id_of);
        assert_eq!(
            BTreeSet::from(jvm).len(),
            3,
            "Java, Scala and Kotlin run three distinct passes: {jvm:?}"
        );

        let mut owners: BTreeMap<EdgePassId, Vec<Language>> = BTreeMap::new();
        for language in ANALYZABLE {
            owners
                .entry(edge_pass_id_of(language))
                .or_default()
                .push(language);
        }
        for (id, languages) in &owners {
            assert!(
                languages.len() == 1
                    || *languages == vec![Language::JavaScript, Language::TypeScript],
                "{id:?} is shared by unrelated languages {languages:?}"
            );
        }
        assert_eq!(
            owners.keys().copied().collect::<Vec<_>>(),
            EdgePassId::ALL
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            "every declared pass id is owned, and no language reports an undeclared one"
        );
    }

    /// `LanguageEdgePass` has no `ecosystem()` on purpose -- `LanguageSupport` is the
    /// single owner -- which only holds if the languages sharing a pass agree. This is the
    /// assertion `edge_passes` makes at runtime, checked here against the whole registry.
    #[test]
    fn languages_sharing_a_pass_agree_on_their_ecosystem() {
        let mut ecosystem_of: BTreeMap<EdgePassId, (Language, UsageEcosystem)> = BTreeMap::new();
        for language in ANALYZABLE {
            let support = support_of(language);
            let id = edge_pass_id_of(language);
            match ecosystem_of.get(&id) {
                None => {
                    ecosystem_of.insert(id, (language, support.ecosystem()));
                }
                Some((owner, ecosystem)) => assert_eq!(
                    *ecosystem,
                    support.ecosystem(),
                    "{language:?} and {owner:?} share {id:?} but disagree on their ecosystem"
                ),
            }
        }
        assert_eq!(
            edge_passes().len(),
            ecosystem_of.len(),
            "the collector deduplicates to exactly the distinct pass ids"
        );
    }

    /// `UsageEcosystem::of` delegates here now, and the JVM realm is the reason ecosystem
    /// and language are not the same thing.
    #[test]
    fn the_jvm_trio_shares_one_ecosystem_across_three_passes() {
        for language in [Language::Java, Language::Scala, Language::Kotlin] {
            assert_eq!(support_of(language).ecosystem(), UsageEcosystem::Jvm);
        }
        assert_eq!(UsageEcosystem::of(Language::None), UsageEcosystem::Unknown);
    }

    /// A support must find its own analyzer and no other's: a mis-wired downcast would
    /// silently answer forward queries from the wrong language's declarations.
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn each_support_resolves_only_its_own_forward_query_provider() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp root");
        let project =
            || FileSetProject::new(root.clone(), std::iter::empty::<std::path::PathBuf>());
        let delegates = [
            (
                Language::Java,
                AnalyzerDelegate::Java(JavaAnalyzer::from_project(project())),
            ),
            (
                Language::Go,
                AnalyzerDelegate::Go(GoAnalyzer::from_project(project())),
            ),
            (
                Language::Cpp,
                AnalyzerDelegate::Cpp(CppAnalyzer::from_project(project())),
            ),
            (
                Language::JavaScript,
                AnalyzerDelegate::JavaScript(JavascriptAnalyzer::from_project(project())),
            ),
            (
                Language::TypeScript,
                AnalyzerDelegate::TypeScript(TypescriptAnalyzer::from_project(project())),
            ),
            (
                Language::Python,
                AnalyzerDelegate::Python(PythonAnalyzer::from_project(project())),
            ),
            (
                Language::Rust,
                AnalyzerDelegate::Rust(RustAnalyzer::from_project(project())),
            ),
            (
                Language::Php,
                AnalyzerDelegate::Php(PhpAnalyzer::from_project(project())),
            ),
            (
                Language::Scala,
                AnalyzerDelegate::Scala(ScalaAnalyzer::from_project(project())),
            ),
            (
                Language::CSharp,
                AnalyzerDelegate::CSharp(CSharpAnalyzer::from_project(project())),
            ),
            (
                Language::Ruby,
                AnalyzerDelegate::Ruby(RubyAnalyzer::from_project(project())),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::Kotlin(KotlinAnalyzer::from_project(project())),
            ),
        ];

        for (owner, delegate) in delegates {
            let analyzer = MultiAnalyzer::new(BTreeMap::from([(owner, delegate)]));
            for language in ANALYZABLE {
                let provider = support_of(language).forward_query_provider(&analyzer);
                assert_eq!(
                    provider.is_some(),
                    language == owner,
                    "{language:?} support resolved against a {owner:?}-only analyzer"
                );
            }
        }
    }

    /// `brokk-bifrost-core` cannot reach this CLAIMS SEAM registry, but it has
    /// to name declarations found in the files inference claims -- an
    /// unclaimed-extension file renders its qualified name in the claiming
    /// language rather than `Language::None` (#1878). Its copy of the fact must
    /// track this one.
    #[test]
    fn core_claiming_language_matches_the_claims_seam() {
        assert_eq!(
            [INCLUDE_CLAIMING_LANGUAGE].as_slice(),
            claim_inferring_languages(),
            "core's INCLUDE_CLAIMING_LANGUAGE must name exactly the claim-inferring registry"
        );
    }
}
