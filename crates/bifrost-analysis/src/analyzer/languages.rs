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
use crate::analyzer::store::LimitedQueryRows;
use crate::analyzer::usages::get_definition::{
    BoundedResolution, DefinitionLookupOutcome, RustTypeLookupCache,
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
    AnalyzerDefinitionLookup, BoundedDefinitionLookup, CodeUnit, ForwardQueryProvider, IAnalyzer,
    Language, ParserFlavor, ProjectFile, Range, SignatureMetadata, cpp, csharp, go, java, js_ts,
    kotlin, php, python, ruby, rust, scala, structural,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use std::any::Any;
use std::sync::Arc;

pub(crate) trait LanguageSupport: Send + Sync {
    /// The `Language` variant this support serves. Must equal the registry match key.
    fn language(&self) -> Language;

    /// The name universe this language's declarations belong to.
    ///
    /// The single owner of ecosystem knowledge: [`UsageEcosystem::of`] delegates here,
    /// and the edge-pass collector derives a pass's ecosystem from the supports that
    /// own it rather than asking the pass. A pass shared by several languages (JS/TS)
    /// requires those languages to agree here, which [`edge_passes`] asserts.
    fn ecosystem(&self) -> UsageEcosystem;

    /// Graph-backed usage strategy driving the `UsageFinder` query path.
    fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;

    /// The whole-workspace edge pass serving this language, or `None` when the
    /// language contributes no workspace edges at all. Languages served by one
    /// resolver return the *same* pass: JavaScript and TypeScript share one, while
    /// Java, Scala and Kotlin return three distinct passes inside one ecosystem.
    fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> {
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

    /// Separator between a package name and its parent. Only Go and C++ differ from the
    /// dotted default.
    fn package_separator(&self) -> &'static str {
        "."
    }

    /// How dead-code analysis proves this language's candidates.
    fn dead_code(&self) -> DeadCodeSupport {
        DeadCodeSupport::default()
    }

    /// Bounded structural receiver resolution, or `None` when receiver queries for this
    /// language take another route (Java runs a resolution session, JS/TS runs its own
    /// syntax-index path) or are unsupported entirely.
    ///
    /// This is the single owner of the structural-receiver capability: the receiver query
    /// gate admits exactly the languages that answer `Some` here, so an absent resolver
    /// yields the `receiver_analysis_language_unsupported` report rather than reaching a
    /// dispatch that cannot serve it.
    fn structural_receiver(&self) -> Option<&'static dyn StructuralReceiverResolver> {
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

    /// Unbounded `get_type_by_location` resolution, or `None` when the language has no
    /// type lookup implementation. Absence is reported to the caller as
    /// `TypeLookupStatus::UnsupportedLanguage`, not as a silent empty result.
    fn type_lookup(&self) -> Option<&'static dyn TypeLookupResolver> {
        None
    }

    /// Candidate files this language contributes to a usage query beyond the generic
    /// import-graph and text-search routes. Consulted on the default route only: an
    /// explicit candidate provider is the caller's whole answer and is never augmented.
    fn candidate_augmentation(&self, _ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> {
        None
    }

    /// How a fully qualified name is spelled for a reader. The default is the indexed
    /// spelling itself; the three languages that override strip indexer-only decoration
    /// their users never type (Scala's object `$`, C#'s generic arity and `global::`
    /// prefix, TypeScript's `$static` static-member marker).
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol.to_string()
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

    /// Build this language's lazily constructed usage indexes ahead of demand, if it has
    /// any worth warming. Called for every language on a workspace whether or not the
    /// workspace analyzes it, so an implementation resolves its own analyzer first and
    /// does nothing when it is absent.
    fn warm_usage_analysis(&self, _analyzer: &dyn IAnalyzer) {}

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

    /// Location-bearing edges for the `usage_graph` consumer. `None` when the workspace
    /// does not analyze this pass's languages; the consumer records nothing and reports
    /// no diagnostic.
    fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites>;

    /// Reference-kind counts for the workspace-graph consumer, in whichever node
    /// identity this pass keys by.
    fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights>;
}

/// Location-bearing edges, always fqn-keyed. Unlike [`LanguageEdgeWeights`] this needs no
/// enum: every language, JS/TS included, produces one shape on the sites path.
pub(crate) struct LanguageEdgeSites(pub(crate) UsageEdges);

/// Reference-kind counts in this pass's node identity. JS/TS keys by `{file, fqn}` because
/// same-named exports in different modules are different declarations; every other pass
/// keys by fqn within its ecosystem.
pub(crate) enum LanguageEdgeWeights {
    Fqn(UsageEdgeWeights),
    Scoped(JsTsScopedUsageEdges),
}

/// Inputs to a sites scan. `keep_file` drops out-of-scope caller files before parsing and
/// is called once per file, never per reference.
pub(crate) struct EdgeSiteScanCtx<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) fqns: &'a HashSet<String>,
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
    pub(crate) pass: &'static dyn LanguageEdgePass,
}

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
            let Some(pass) = support.edge_pass().filter(|pass| pass.id() == id) else {
                continue;
            };
            match &entry {
                None => {
                    entry = Some(EdgePassEntry {
                        id,
                        ecosystem: support.ecosystem(),
                        pass,
                    });
                }
                Some(entry) => assert_eq!(
                    entry.ecosystem,
                    support.ecosystem(),
                    "{language:?} shares edge pass {id:?} but disagrees on its ecosystem"
                ),
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
/// in bulk, Kotlin has no bulk proof because every Kotlin candidate takes the per-symbol
/// path, and a candidate that reaches a path its language does not serve is skipped as
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

pub(crate) trait TypeLookupResolver: Send + Sync {
    fn resolve_type(&self, query: TypeLookupQuery<'_>) -> TypeLookupOutcome;
}

/// Every input the per-language type resolvers draw on. They consume different subsets:
/// the JVM, Scala and JS/TS resolvers need the batch's definition lookup (and set its
/// language first), Rust needs the batch's type cache, JS/TS needs the dialect. Passing
/// the whole batch state keeps that a property of each resolver rather than a mode the
/// caller has to select.
pub(crate) struct TypeLookupQuery<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) support: &'a AnalyzerDefinitionLookup<'a>,
    pub(crate) file: &'a ProjectFile,
    pub(crate) language: Language,
    pub(crate) source: &'a str,
    pub(crate) tree: Option<&'a tree_sitter::Tree>,
    pub(crate) site: &'a ResolvedReferenceSite,
    pub(crate) rust_cache: &'a mut RustTypeLookupCache,
}

pub(crate) struct CandidateCtx<'a> {
    pub(crate) analyzer: &'a dyn IAnalyzer,
    pub(crate) target: &'a CodeUnit,
    pub(crate) cancellation: &'a CancellationToken,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
    use crate::analyzer::{
        CSharpAnalyzer, CppAnalyzer, FileSetProject, GoAnalyzer, JavaAnalyzer, JavascriptAnalyzer,
        KotlinAnalyzer, PhpAnalyzer, PythonAnalyzer, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer,
        TypescriptAnalyzer,
    };
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
    /// candidates are always proven in bulk, and Kotlin has no bulk proof because every
    /// Kotlin candidate takes the per-symbol path; Java and JS/TS answer no structural
    /// receiver because their receiver analysis runs another route entirely (a resolution
    /// session, and the JS/TS syntax index reached through `facts`); and C++, PHP, Python
    /// and Ruby have a bounded receiver resolver but no unbounded type lookup, so every
    /// location query against them still reports `TypeLookupStatus::UnsupportedLanguage`.
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
language   | ecosystem            | pass   | sep | strategy | bulk   | recv | facts | type | hl
Java       | Jvm                  | Java   | .   | yes      | Java   | -    | -     | yes  | yes
Go         | Go                   | Go     | /   | yes      | Go     | yes  | -     | yes  | yes
Cpp        | Cpp                  | Cpp    | ::  | -        | Cpp    | yes  | -     | -    | yes
JavaScript | JavaScriptTypeScript | JsTs   | .   | yes      | JsTs   | -    | yes   | yes  | yes
TypeScript | JavaScriptTypeScript | JsTs   | .   | yes      | JsTs   | -    | yes   | yes  | yes
Python     | Python               | Python | .   | -        | Python | yes  | -     | -    | yes
Rust       | Rust                 | Rust   | .   | yes      | Rust   | yes  | -     | yes  | yes
Php        | Php                  | Php    | .   | yes      | Php    | yes  | -     | -    | yes
Scala      | Jvm                  | Scala  | .   | yes      | Scala  | yes  | -     | yes  | yes
CSharp     | CSharp               | CSharp | .   | yes      | CSharp | yes  | -     | yes  | yes
Ruby       | Ruby                 | Ruby   | .   | yes      | Ruby   | yes  | -     | -    | yes
Kotlin     | Jvm                  | Kotlin | .   | yes      | -      | yes  | -     | yes  | yes
";

    fn mark(present: bool) -> &'static str {
        if present { "yes" } else { "-" }
    }

    fn capability_matrix() -> String {
        let mut rendered = String::from(
            "language   | ecosystem            | pass   | sep | strategy | bulk   | recv | facts | type | hl\n",
        );
        for language in ANALYZABLE {
            let support = support_of(language);
            let dead_code = support.dead_code();
            rendered.push_str(&format!(
                "{:<10} | {:<20} | {:<6} | {:<3} | {:<8} | {:<6} | {:<4} | {:<5} | {:<4} | {}\n",
                format!("{language:?}"),
                format!("{:?}", support.ecosystem()),
                support
                    .edge_pass()
                    .map_or_else(|| "-".to_string(), |pass| format!("{:?}", pass.id())),
                support.package_separator(),
                mark(dead_code.strategy.is_some()),
                dead_code
                    .bulk
                    .map_or_else(|| "-".to_string(), |bulk| format!("{:?}", bulk.id())),
                mark(support.structural_receiver().is_some()),
                mark(support.receiver_facts().is_some()),
                mark(support.type_lookup().is_some()),
                mark(support.highlight_query().is_some()),
            ));
        }
        rendered
    }

    #[test]
    fn the_capability_matrix_matches_its_snapshot() {
        assert_eq!(capability_matrix(), CAPABILITY_MATRIX);
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
        support_of(language)
            .edge_pass()
            .unwrap_or_else(|| panic!("{language:?} must have an edge pass"))
            .id()
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
}
