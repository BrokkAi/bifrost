use super::read_source;

use crate::analyzer::common::IdentifierSeek;
use crate::analyzer::common::decorated_identifier_seeks;
use crate::analyzer::common::language_for_file;

use crate::analyzer::languages::language_support_for_hook;

use crate::analyzer::lexical_definitions::LexicalBindingResolution;
use crate::analyzer::lexical_definitions::LexicalDefinition;
use crate::analyzer::lexical_definitions::resolve_lexical_binding;

use crate::analyzer::read_ledger::IndexFamily;
use crate::analyzer::read_ledger::ReadKey;

use crate::analyzer::usages::common::namespace_prefixes;

use crate::analyzer::usages::receiver_analysis::ReceiverBudgetLimit;

pub(crate) use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
pub(crate) use crate::analyzer::usages::reference_site::SourceLocationRequest;
pub(crate) use crate::analyzer::usages::reference_site::resolve_reference_site_with_line_starts;

use crate::analyzer::QueryScope;
use crate::analyzer::QueryToken;

use brokk_bifrost_core::analyzer::definition_lookup::sort_units;

use crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity;

use crate::analyzer::structural::PrecedenceTier;

use serde::Deserialize;
use serde::Serialize;

use crate::analyzer::AnalyzerDefinitionLookup;
use crate::analyzer::AnalyzerQueryScope;
use crate::analyzer::BoundedDefinitionLookup;
use crate::analyzer::CodeUnit;
use crate::analyzer::DispatchExtensibility;
use crate::analyzer::IAnalyzer;

use crate::analyzer::Language;
use crate::analyzer::ProjectFile;
use crate::analyzer::Range;

use crate::cancellation::CancellationToken;

use crate::hash::HashMap;
use crate::hash::HashSet;

use crate::navigation::NavigationOperation;

use crate::path_utils::rel_path_string;

use crate::profiling;

use crate::text_utils::compute_line_starts;

use brokk_bifrost_core::analyzer::weighted_cache::build_weighted_cache;
use brokk_bifrost_core::analyzer::weighted_cache::weight_source_text;

use moka::sync::Cache;

use std::sync::Arc;
use std::sync::OnceLock;

use tree_sitter::Node;
use tree_sitter::Parser;
use tree_sitter::Tree;

#[doc(hidden)]
pub const CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC: &str = "unproven_cpp_link_unit";
#[doc(hidden)]
pub struct DefinitionNavigationSelection {
    #[doc(hidden)]
    pub targets: Vec<NavigationTarget>,
    #[doc(hidden)]
    pub structure_unavailable: bool,
    #[doc(hidden)]
    pub unproven_link_unit: bool,
    #[doc(hidden)]
    pub truncated: bool,
}

pub(crate) const NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC: &str = "navigation_targets_truncated";
#[doc(hidden)]
pub const PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC: &str = "partial_import_boundary";
#[doc(hidden)]
pub const PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC: &str = "partial_import_unresolved";
#[doc(hidden)]
pub const IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC: &str = "import_bindings_truncated";
#[doc(hidden)]
pub const CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC: &str =
    "cpp_navigation_structure_unavailable";
/// Maximum navigation targets retained for one reference.
///
/// This is deliberately a per-result bound. Dividing it by the number of
/// requests in a batch made unrelated references change a C++ answer: a
/// request with two valid targets became a one-target truncated answer in a
/// large batch (#4512).
#[doc(hidden)]
pub const MAX_NAVIGATION_TARGETS_PER_RESULT: usize = 256;

#[doc(hidden)]
pub fn summary_step(
    session: Option<&brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession>,
) -> bool {
    crate::analyzer::resolution::charge_summary_step(session)
}

#[doc(hidden)]
pub fn record_hierarchy_parents(
    parents: &mut HashMap<CodeUnit, CodeUnit>,
    owner: &CodeUnit,
    ancestors: &[CodeUnit],
) {
    for ancestor in ancestors {
        parents
            .entry(ancestor.clone())
            .or_insert_with(|| owner.clone());
    }
}

#[doc(hidden)]
pub fn record_member_trace_found<Owner, MakeOwner>(
    found: &mut HashMap<CodeUnit, (Owner, usize)>,
    candidates: &[CodeUnit],
    make_owner: MakeOwner,
    depth: usize,
) where
    MakeOwner: Fn() -> Owner,
{
    for candidate in candidates {
        found
            .entry(candidate.clone())
            .or_insert_with(|| (make_owner(), depth));
    }
}

#[doc(hidden)]
pub fn query_limited_definition_units(
    session: &ResolutionSession,
    query: impl FnOnce(usize) -> brokk_bifrost_core::analyzer::query_batch::LimitedQueryRows<CodeUnit>,
) -> Vec<CodeUnit> {
    crate::analyzer::definition_lookup::sort_dedup_units(session.query_limited_rows(query))
}

#[doc(hidden)]
pub fn fqn_direct_children(
    owners: Vec<CodeUnit>,
    mut query: impl FnMut(&CodeUnit) -> Vec<CodeUnit>,
    mut observe_cancellation: impl FnMut() -> bool,
) -> Vec<CodeUnit> {
    let mut children = Vec::new();
    for owner in owners {
        children.extend(query(&owner));
        if !observe_cancellation() {
            return Vec::new();
        }
    }
    crate::analyzer::definition_lookup::sort_dedup_units(children)
}

#[doc(hidden)]
pub fn record_external_member_identity(
    slot: &mut Option<ResolverOwnedExternalCalleeIdentity>,
    language: Language,
    owner_fqn: &str,
    member: &str,
) {
    let identity =
        ResolverOwnedExternalCalleeIdentity::new(language, owner_fqn.to_owned(), member.to_owned());
    debug_assert!(
        slot.as_ref().is_none_or(|existing| existing == &identity),
        "one call cannot resolve to conflicting external identities"
    );
    *slot = Some(identity);
}

#[doc(hidden)]
pub fn record_companion_owner<S: std::hash::BuildHasher>(
    companion_of: &mut std::collections::HashMap<CodeUnit, CodeUnit, S>,
    owner: &CodeUnit,
    companion: &CodeUnit,
) {
    companion_of
        .entry(companion.clone())
        .or_insert_with(|| owner.clone());
}

#[doc(hidden)]
pub mod call_sites;

#[doc(hidden)]
pub fn member_precedence_tier(depth: usize) -> PrecedenceTier {
    if depth == 0 {
        PrecedenceTier::OwnMember
    } else {
        PrecedenceTier::InheritedMember
    }
}
pub mod trace;

#[doc(hidden)]
pub fn record_native_external_route(name: String) {
    trace::record_named_boundary(name);
}

#[doc(hidden)]
pub fn record_native_external_route_with_target(name: String, target: String) {
    trace::record_named_boundary_with_target(name, target);
}

pub(crate) use brokk_bifrost_core::analyzer::usages::resolution_session;

pub use call_sites::CallSyntaxKind;

pub use call_sites::call_signature_context;

pub(crate) use call_sites::CallSiteSyntax;
pub(crate) use call_sites::ExactCallReference;
pub(crate) use call_sites::ExactCallReferenceGap;
pub(crate) use call_sites::call_reference_ranges_in_tree;
pub(crate) use call_sites::call_reference_requires_point_lookup;
pub(crate) use call_sites::call_site_syntax_for_reference;
pub(crate) use call_sites::exact_call_reference_for_call;
pub(crate) use call_sites::is_call_reference_range_in_tree;
pub(crate) use call_sites::range_is_call_keyword_label;

pub(crate) use resolution_session::BoundedResolution;
pub(crate) use resolution_session::ResolutionSession;

#[doc(hidden)]
pub fn session_scope_step(session: Option<&ResolutionSession>) -> bool {
    ResolutionSession::scope_step_with_optional_session(session)
}

pub use trace::DispatchQuality;
pub use trace::ResolutionTraceResult;
pub use trace::TraceCandidate;
pub use trace::TraceCandidateRef;
pub use trace::TraceCompleteness;
pub use trace::boundary_evidence;
pub use trace::dispatch_quality_for_status;
pub use trace::resolve_definition_batch_with_trace;

/// Resolve a bare `name` against the lexically enclosing scope chain, innermost
/// first — the language-agnostic generalization of Java's nested-type resolution
/// (`java_nested_type_from_context`).
///
/// Finds the enclosing declaration at `byte` via the generic `enclosing_code_unit`
/// primitive (which every analyzer implements), then walks its fully-qualified name
/// outward one segment at a time, trying `{scope}.{name}` at each level and
/// returning the innermost match. This makes a bare reference inside `mod b` (Rust)
/// / `namespace B` (C++/C#) / `class B` resolve to `B`'s member rather than a
/// same-named sibling scope's — the #431 scope-blind collapse — because it uses the
/// reference's *position* instead of a flat, position-blind short-name map.
///
/// Walking fqn segments (rather than `parent_of`) is what makes it uniform across
/// languages: scopes that are CodeUnits (Rust modules) and scopes that are only fqn
/// prefixes (C#/C++ namespaces, which are not indexed as units) are handled the same
/// way. `accept` filters the wanted declaration kind (e.g. `CodeUnit::is_class`).
#[doc(hidden)]
pub fn resolve_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }
    resolve_qualified_in_enclosing_scopes(analyzer, file, name, byte, accept)
}

/// The dotted-reference generalization of [`resolve_in_enclosing_scopes`]:
/// `internal::EachMatcher` inside `namespace testing` must resolve to
/// `testing::internal::EachMatcher` — the reference is multi-segment, so the
/// single-segment walk above cannot try it (tier-4 gmock shape, #1129's
/// sibling).
///
/// Both sides are now interned segments (M2). The reference is parsed once into
/// an [`crate::analyzer::fq_name::FqName`] via
/// [`crate::analyzer::symbol_lookup::parse_symbol_path_fq`] (which honors the
/// language's full separator set — `::`, `.`, `\`, `/`, `+` — and per-language
/// normalization), and the enclosing scope's own structured `fq` supplies the
/// prefix chain. Composing a candidate is a segment push, not a
/// `format!("{scope}.{reference}")`, so the M1-era reference-normalization shim
/// (`normalize_reference_to_fq_segments`) is gone: a `::`-qualified reference
/// resolving to a `.`-joined candidate falls straight out of the segment
/// rendering (#1162), with no per-call string massaging.
///
/// The scope prefix walk descends only across boundaries the native spelling
/// renders as a literal `.`, so a C++ `::`-headed namespace scope
/// (`cutlass::gemm::warp.OperandSharedStorage`) is never descended into its
/// sibling namespaces — exactly the legacy dot-only `namespace_prefixes` walk,
/// which is why issue #1163 stays pinned until M4 flips it deliberately.
///
/// Cache-loaded scope units carry an empty `fq` until persistence ships
/// segments (M3); they take the string fallback arm below, which renders the
/// reference to the same `.`-joined normalization the deleted shim produced and
/// walks the verbatim scope string. Both arms are proven identical by the
/// `issue_1162_separator_aware_enclosing_scope` suite and the dual-arm unit
/// tests. The fallback arm is deleted in M4.
pub(super) fn resolve_qualified_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if reference.is_empty() {
        return None;
    }
    let language = language_for_file(file);
    let interner = crate::analyzer::fq_name::segment_interner();
    let reference_fq =
        crate::analyzer::symbol_lookup::parse_symbol_path_fq(language, reference, interner);
    if reference_fq.is_empty() {
        return None;
    }
    let range = Range {
        start_byte: byte,
        end_byte: byte + 1,
        start_line: 0,
        end_line: 0,
    };
    let scope_unit = analyzer.enclosing_code_unit(file, &range)?;

    // The enclosing scope unit always comes from FileState declarations, which
    // carry a populated structured `fq` (extracted at M1, rehydrated from
    // persisted segments at M3), so the composition is a pure segment push. The
    // M2-era empty-fq string fallback (which walked the verbatim scope string and
    // rendered the reference via `display`) is deleted; both sides are segments.
    if scope_unit.fq().is_empty() {
        return None;
    }
    resolve_qualified_name_in_shrinking_scopes_fq(
        language,
        scope_unit.fq(),
        &reference_fq,
        interner,
        || true,
        |fqn| analyzer.definitions(fqn).collect(),
        accept,
    )
}

/// Segment-composed sibling of [`resolve_qualified_name_in_shrinking_scopes`]:
/// tries `{scope} + reference` at the full enclosing scope, then at each
/// progressively shorter prefix of `scope`, composing each candidate by pushing
/// the reference's segments onto the scope prefix (no separator inference) and
/// rendering natively for the string-keyed `definitions` lookup.
///
/// A prefix boundary is a valid cut point only where the native rendering
/// places a literal `.`, which reproduces the legacy dot-only
/// `namespace_prefixes` walk exactly: a `::`-joined C++ namespace head, a `/`
/// path join, or a `$` nesting boundary is not a `.`, so the walk never
/// descends across it. `charge_hop` is polled once per attempted prefix (same
/// count as the string core), so budget-charging callers truncate identically.
pub(super) fn resolve_qualified_name_in_shrinking_scopes_fq(
    language: Language,
    scope: &crate::analyzer::fq_name::FqName,
    reference: &crate::analyzer::fq_name::FqName,
    interner: &crate::analyzer::fq_name::SegmentInterner,
    charge_hop: impl FnMut() -> bool,
    definitions_for: impl FnMut(&str) -> Vec<CodeUnit>,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let segments = scope.segments();
    let prefix_lengths = (1..=segments.len()).rev().filter(|&len| {
        len == segments.len()
            || interner.separator_between(segments[len - 1], segments[len], language) == "."
    });
    resolve_qualified_name_in_fq_prefixes(
        language,
        scope,
        reference,
        interner,
        prefix_lengths,
        charge_hop,
        definitions_for,
        accept,
    )
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn resolve_qualified_name_in_fq_prefixes(
    language: Language,
    scope: &crate::analyzer::fq_name::FqName,
    reference: &crate::analyzer::fq_name::FqName,
    interner: &crate::analyzer::fq_name::SegmentInterner,
    prefix_lengths: impl IntoIterator<Item = usize>,
    mut charge_hop: impl FnMut() -> bool,
    mut definitions_for: impl FnMut(&str) -> Vec<CodeUnit>,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    for len in prefix_lengths {
        debug_assert!(len <= scope.segments().len());
        if !charge_hop() {
            break;
        }
        let mut candidate = crate::analyzer::fq_name::FqName::new();
        for &id in &scope.segments()[..len] {
            candidate.push(id);
        }
        for &id in reference.segments() {
            candidate.push(id);
        }
        let candidate_str = candidate.display_native(language, interner);
        if let Some(unit) = definitions_for(&candidate_str)
            .into_iter()
            .find(|unit| accept(unit))
        {
            return Some(unit);
        }
    }
    None
}

/// Budget-parametric core shared by the empty-fq fallback arm of
/// [`resolve_qualified_in_enclosing_scopes`]
/// and C#'s bounded fork (`resolve_csharp_in_enclosing_scopes`): try
/// `{prefix}.{reference}` at `scope`, then at each progressively shorter
/// dotted prefix of `scope` in turn (never the bare top level — see the doc
/// comment above), returning the first hit `definitions_for` reports that
/// `accept` approves.
///
/// `definitions_for` supplies the definitions source (an unbounded
/// `analyzer.definitions` call, or a session-aware/budget-charging one), and
/// `charge_hop` gates each prefix attempt (an always-`true` closure for
/// unbounded callers). Once `charge_hop` declines, the walk stops
/// immediately without formatting or looking up further prefixes — matching
/// how csharp's/java's per-hop `scope_step` budgets truncate the walk today.
#[doc(hidden)]
pub fn resolve_qualified_name_in_shrinking_scopes(
    scope: &str,
    reference: &str,
    mut charge_hop: impl FnMut() -> bool,
    mut definitions_for: impl FnMut(&str) -> Vec<CodeUnit>,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    namespace_prefixes(scope)
        .take_while(|prefix| !prefix.is_empty())
        .map_while(|prefix| charge_hop().then_some(prefix))
        .find_map(|prefix| {
            let candidate = format!("{prefix}.{reference}");
            definitions_for(&candidate)
                .into_iter()
                .find(|unit| accept(unit))
        })
}

#[doc(hidden)]
pub const SCALA_UNSUPPORTED_CALL_TARGET_SHAPE: &str = "unsupported_scala_call_target_shape";
#[doc(hidden)]
pub const SCALA_UNSUPPORTED_RECEIVER: &str = "unsupported_scala_receiver";

#[derive(Debug, Clone)]
pub struct DefinitionLookupRequest {
    pub file: ProjectFile,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
}

impl DefinitionLookupRequest {
    fn as_source_location(&self) -> SourceLocationRequest {
        crate::analyzer::usages::source_location_request(
            &self.file,
            self.line,
            self.column,
            self.start_byte,
            self.end_byte,
        )
    }
}

#[derive(Debug, Clone)]
pub struct DefinitionLookupOutcome {
    /// Explicit declarations proved by an activated semantic model.
    pub modeled_definitions: Vec<crate::analyzer::semantic_model::SemanticModelSymbol>,
    pub status: DefinitionLookupStatus,
    pub reference: Option<ResolvedReferenceSite>,
    pub definitions: Vec<CodeUnit>,
    pub lexical_definition: Option<LexicalDefinition>,
    pub diagnostics: Vec<DefinitionLookupDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedValueIdentityKind {
    WorkspaceDeclaration,
    ActiveSemanticModel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValueIdentity {
    pub kind: ResolvedValueIdentityKind,
    pub identity: String,
    pub aliases: Vec<String>,
}

impl DefinitionLookupOutcome {
    pub fn resolved_reference_target(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .map(|reference| reference.text.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationTarget {
    pub code_unit: CodeUnit,
    pub declaration_range: Option<Range>,
}

#[derive(Debug, Clone)]
pub struct NavigationLookupOutcome {
    #[doc(hidden)]
    pub modeled_definitions: Vec<crate::analyzer::semantic_model::SemanticModelSymbol>,
    pub status: DefinitionLookupStatus,
    #[doc(hidden)]
    pub reference: Option<ResolvedReferenceSite>,
    pub targets: Vec<NavigationTarget>,
    pub lexical_definition: Option<LexicalDefinition>,
    pub diagnostics: Vec<DefinitionLookupDiagnostic>,
    #[doc(hidden)]
    pub structure_unavailable: bool,
    #[doc(hidden)]
    pub unproven_link_unit: bool,
    #[doc(hidden)]
    pub truncated: bool,
    /// The resolver's own call evidence for this request, retained so the
    /// navigation route can answer a call-target batch without discarding it.
    #[doc(hidden)]
    pub evidence: CallEvidence,
}

impl NavigationLookupOutcome {
    pub fn resolved_reference_target(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .map(|reference| reference.text.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct CallTargetLookupOutcome {
    pub outcome: DefinitionLookupOutcome,
    /// Which definition operation supplied this call target. The call-binding
    /// consumer may retain a source candidate from an incomplete answer only
    /// when the selected-native operation itself supplied it.
    pub authority: DefinitionResolutionAuthority,
    /// Structured classification of how the resolved callable supplies its
    /// receiver, retained from the same language-resolution pass that produced
    /// `outcome`. This shapes model applicability without identifying a method
    /// target.
    #[doc(hidden)]
    pub call_application: CallApplicationKind,
    /// Exact declaration-side evidence about whether the selected callable can
    /// dispatch beyond itself. `None` means the resolver did not prove it.
    #[doc(hidden)]
    pub dispatch_extensibility: Option<DispatchExtensibility>,
    /// Canonical external callee identity carried from the exact declaration
    /// proof that selected it, together with every call-shape fact needed to
    /// bind a model. This is stronger than recovering a name or arity from
    /// `outcome` and the structural call independently: presence proves one
    /// modeled callable rather than merely a spelling that crossed the
    /// workspace boundary.
    #[doc(hidden)]
    pub exact_external_call: Option<ExactExternalCallProof>,
    /// Resolver-owned external owner/member identity. Unlike
    /// `exact_external_call`, this carries no arity or receiver evidence and
    /// must never mint an exact semantic procedure target on its own.
    #[doc(hidden)]
    pub external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
    pub structure_unavailable: bool,
    pub unproven_link_unit: bool,
    pub truncated: bool,
}

impl CallTargetLookupOutcome {
    /// One resolver answer with every fact it proved about the call retained,
    /// and no navigation limit reached.
    ///
    /// The evidence fields are copied from the resolution rather than decided
    /// here, because only the resolver knows whether it proved anything. A
    /// route that decides instead -- by language, as this one did until #3496
    /// -- silently drops the proof of any language it has not been taught
    /// about.
    #[doc(hidden)]
    pub fn from_resolution(resolution: DefinitionResolution) -> Self {
        Self {
            outcome: resolution.outcome,
            authority: resolution.evidence.authority,
            call_application: resolution.evidence.call_application,
            dispatch_extensibility: resolution.evidence.dispatch_extensibility,
            exact_external_call: resolution.evidence.exact_external_call,
            external_callee_identity: resolution.evidence.external_callee_identity,
            structure_unavailable: false,
            unproven_link_unit: false,
            truncated: false,
        }
    }

    /// The one source declaration an incomplete selected-native Java lookup
    /// retained. Consumers may use its source signature for candidate-local
    /// relations, but must keep the lookup's original incomplete completion.
    pub fn unique_incomplete_native_java_source_candidate(&self) -> Option<(&CodeUnit, &str)> {
        let source_access_is_open = self
            .outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "java-source-access-open");
        if self.authority != DefinitionResolutionAuthority::NativeJavaSelected
            || self.outcome.status != DefinitionLookupStatus::Incomplete
            || !self.outcome.modeled_definitions.is_empty()
            || self.outcome.lexical_definition.is_some()
            || (self.structure_unavailable && !source_access_is_open)
            || self.unproven_link_unit
            || self.truncated
            || !self
                .outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "incomplete_binding")
        {
            return None;
        }
        let [candidate] = self.outcome.definitions.as_slice() else {
            return None;
        };
        let reason = self
            .outcome
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.kind == "incomplete_binding")?
            .message
            .as_str();
        Some((candidate, reason))
    }

    /// The one source declaration an incomplete selected-native Java or Go
    /// lookup retained. Consumers may use its source signature for
    /// candidate-local relations, but must keep the lookup's original
    /// incomplete completion.
    pub fn unique_incomplete_native_source_candidate(&self) -> Option<(&CodeUnit, &str)> {
        let source_access_is_open = self
            .outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == "java-source-access-open");
        if !matches!(
            self.authority,
            DefinitionResolutionAuthority::NativeJavaSelected
                | DefinitionResolutionAuthority::NativeGoSelected
        ) || self.outcome.status != DefinitionLookupStatus::Incomplete
            || !self.outcome.modeled_definitions.is_empty()
            || self.outcome.lexical_definition.is_some()
            || (self.structure_unavailable && !source_access_is_open)
            || self.unproven_link_unit
            || self.truncated
            || !self
                .outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "incomplete_binding")
        {
            return None;
        }
        let [candidate] = self.outcome.definitions.as_slice() else {
            return None;
        };
        let reason = self
            .outcome
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.kind == "incomplete_binding")?
            .message
            .as_str();
        Some((candidate, reason))
    }
}

/// One resolver-owned proof for an exact external callable and its applicable
/// call shape.
///
/// The canonical callee, receiver application, dispatch extensibility, and
/// effective argument count must travel together. In particular, a Go call
/// with one written argument can supply several effective arguments when that
/// argument is an exact modeled multi-result call, while a JS/TS direct named
/// import has no receiver even though its package identity is not written at
/// the call site. Consumers must not rebuild these facts from separate display,
/// structural, or semantic representations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct ExactExternalCallProof {
    #[doc(hidden)]
    pub canonical_callee: Box<str>,
    #[doc(hidden)]
    pub call_application: CallApplicationKind,
    #[doc(hidden)]
    pub dispatch_extensibility: Option<DispatchExtensibility>,
    #[doc(hidden)]
    pub parameter_count: u32,
    /// The source module's configured, prepared JDK artifact, retained only
    /// after the selected callee declaration names the same exact artifact.
    /// A separate model and dispatch check is still required for an obligation.
    #[doc(hidden)]
    pub source_jdk_artifact:
        Option<crate::analyzer::semantic_model::SemanticModelActivationEvidence>,
    /// Exact PyPI artifact resolved for this Python callable from installed
    /// artifact state joined to an active semantic profile, and promoted only
    /// by matching defining-binding and provider tokens.
    #[doc(hidden)]
    pub python_runtime_artifact:
        Option<crate::analyzer::semantic_model::SemanticModelActivationEvidence>,
    /// Formal declaration slots copied only from the checked Python defining
    /// binding that promoted this proof.
    #[doc(hidden)]
    pub python_formal_slots:
        Option<Box<[crate::analyzer::lexical_definitions::FormalParameterSlot]>>,
    #[doc(hidden)]
    pub python_model_manifest_sha256: Option<Box<str>>,
    external_member_identity: Option<crate::analyzer::resolution::ExternalMemberIdentity>,
}

impl ExactExternalCallProof {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_external_member_identity(
        mut self,
        identity: Option<crate::analyzer::resolution::ExternalMemberIdentity>,
    ) -> Self {
        self.external_member_identity = identity;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn external_member_identity(
        &self,
    ) -> Option<&crate::analyzer::resolution::ExternalMemberIdentity> {
        self.external_member_identity.as_ref()
    }

    fn package_function(canonical_callee: impl Into<Box<str>>, parameter_count: u32) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            call_application: CallApplicationKind::PackageFunction,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    fn bound_receiver(canonical_callee: impl Into<Box<str>>, parameter_count: u32) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    #[doc(hidden)]
    pub fn go_package_function(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self::package_function(canonical_callee, parameter_count)
    }

    #[doc(hidden)]
    pub fn go_concrete_receiver(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: Some(DispatchExtensibility::Closed),
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    #[doc(hidden)]
    pub fn go_interface_receiver(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: Some(DispatchExtensibility::Open),
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    /// Canonical identity from an exact structured receiver type and selector
    /// when external declaration facts do not prove the method body or its
    /// dispatch closure. This can name a reviewed model lookup, but cannot
    /// discharge the caller's dynamic-dispatch gap.
    #[doc(hidden)]
    pub fn go_receiver_candidate(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self {
            canonical_callee: canonical_callee.into(),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    #[doc(hidden)]
    pub fn js_ts_direct_named_import(
        module_specifier: &str,
        imported_name: &str,
        parameter_count: u32,
    ) -> Self {
        assert!(
            !module_specifier.is_empty(),
            "an imported module must be named"
        );
        assert!(
            !imported_name.is_empty(),
            "an imported callable must be named"
        );
        Self {
            canonical_callee: format!("{module_specifier}.{imported_name}").into_boxed_str(),
            call_application: CallApplicationKind::PackageFunction,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    /// A receiverless call to one member of the language's global object.
    ///
    /// `fetch(url)` writes no receiver, so nothing at the call site spells the
    /// owner. The owner is the global object's own identity, proven by the
    /// modeled declaration rather than by the callee's spelling, and the call
    /// shape is a package function because no written value participates --
    /// exactly as a direct named import is receiverless.
    #[doc(hidden)]
    pub fn js_ts_global_function(global_object: &str, member: &str, parameter_count: u32) -> Self {
        assert!(!global_object.is_empty(), "a global object must be named");
        assert!(!member.is_empty(), "a global member must be named");
        Self::package_function(format!("{global_object}.{member}"), parameter_count)
    }

    #[doc(hidden)]
    pub fn js_ts_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        // JavaScript and TypeScript permit runtime prototype changes. The
        // active callable family proves the selected declaration, not that
        // the language has a closed dispatch universe.
        Self::bound_receiver(format!("{owner}.{member}"), parameter_count)
    }

    /// A call written as `Owner::Path.member(...)` whose owner path an
    /// activated pack publishes.
    ///
    /// Ruby writes the receiver as a constant path and the written value is
    /// the owner's constant itself, so the member is bound to the receiver it
    /// names. Ruby permits reopening a class at runtime, so the reviewed pack
    /// proves the selected declaration, not that the language has a closed
    /// dispatch universe.
    #[doc(hidden)]
    pub fn ruby_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self::bound_receiver(format!("{owner}.{member}"), parameter_count)
    }

    #[doc(hidden)]
    /// An instance call whose external declaration proved one applicable
    /// signature for the written value receiver.
    ///
    /// Java instance methods can be overridden, so the selected signature does
    /// not prove that dispatch is closed.
    pub fn java_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self::bound_receiver(format!("{owner}.{member}"), parameter_count)
    }

    #[doc(hidden)]
    /// A type-qualifier call whose external declaration proved one static
    /// signature. The receiver shape is the proof that no written value
    /// participates; it does not by itself close every other declaration of
    /// the same name.
    pub fn java_static_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self::package_function(format!("{owner}.{member}"), parameter_count)
    }

    /// A C# type-qualified call whose modeled declaration proves one static
    /// signature. The receiverless application is kept with the canonical
    /// owner/member identity so an activated summary can select its formals.
    #[doc(hidden)]
    pub fn csharp_static_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self::package_function(format!("{owner}.{member}"), parameter_count)
    }

    /// A C# instance call whose external declaration proves the receiver's
    /// owner and one applicable signature. The target may still dispatch to
    /// an external override, so the proof leaves dispatch extensibility open.
    #[doc(hidden)]
    pub fn csharp_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self::bound_receiver(format!("{owner}.{member}"), parameter_count)
    }

    #[doc(hidden)]
    /// An external Java constructor has no written receiver. Its declaration
    /// and arity are proved independently of argument conversion and behavior.
    pub fn java_external_constructor(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external constructor owner must be named"
        );
        assert!(!member.is_empty(), "an external constructor must be named");
        Self::package_function(format!("{owner}.{member}"), parameter_count)
    }

    /// An external C# object creation has no written receiver. Its exact
    /// constructor declaration and applicable arity are supplied by the
    /// assembly/model surface, just as for an external Java constructor.
    #[doc(hidden)]
    pub fn csharp_external_constructor(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external constructor owner must be named"
        );
        assert!(!member.is_empty(), "an external constructor must be named");
        let mut proof = Self::package_function(format!("{owner}.{member}"), parameter_count);
        proof.dispatch_extensibility = Some(DispatchExtensibility::Closed);
        proof
    }

    #[doc(hidden)]
    pub fn python_imported_call(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self::python_package_function(canonical_callee, parameter_count)
    }

    #[doc(hidden)]
    pub fn python_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external Python receiver owner must be named"
        );
        assert!(
            !member.is_empty(),
            "an external Python member must be named"
        );
        Self::bound_receiver(format!("{owner}.{member}"), parameter_count)
    }

    #[doc(hidden)]
    pub fn python_builtin_call(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        Self::python_package_function(canonical_callee, parameter_count)
    }

    fn python_package_function(
        canonical_callee: impl Into<Box<str>>,
        parameter_count: u32,
    ) -> Self {
        let canonical_callee = canonical_callee.into();
        assert!(
            !canonical_callee.is_empty(),
            "an external Python package function must be named"
        );
        Self::package_function(canonical_callee, parameter_count)
    }

    /// A Rust method call whose receiver's written type, reached through
    /// built-in reference dereferences only, an activated model declares
    /// with one instance member at the written arity (#3757). A concrete Rust
    /// receiver type dispatches statically, so the selected member is closed.
    ///
    /// `owner` is the dot-joined model key. The member follows the Rust
    /// qualified-call separator, which is where the shared splitter cuts the
    /// text back into the same owner and member.
    #[doc(hidden)]
    pub fn rust_bound_external_member(owner: &str, member: &str, parameter_count: u32) -> Self {
        assert!(
            !owner.is_empty(),
            "an external receiver owner must be named"
        );
        assert!(!member.is_empty(), "an external member must be named");
        Self {
            canonical_callee: format!("{owner}::{member}").into_boxed_str(),
            call_application: CallApplicationKind::BoundReceiver,
            dispatch_extensibility: Some(DispatchExtensibility::Closed),
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    /// A call written as `crate::module::Owner::member(...)` whose leading
    /// segment the Rust resolver proved names no workspace declaration.
    ///
    /// The Rust path is not a receiver expression: `TcpStream::connect(x)`
    /// writes the owner as a type path, so the selected callable is bound to
    /// no written value and the receiver contract is `PackageFunction`
    /// (`has_receiver: false`), exactly as #2596 pinned for the summary key.
    /// The emitted member is the path's terminal segment and the owner is the
    /// dot-joined prefix.
    #[doc(hidden)]
    pub fn rust_external_call(canonical_callee: impl Into<Box<str>>, parameter_count: u32) -> Self {
        let canonical_callee = canonical_callee.into();
        assert!(
            !canonical_callee.is_empty(),
            "a qualified Rust callable must be named"
        );
        Self::package_function(canonical_callee, parameter_count)
    }

    /// A bare C call whose compile-database-scoped header closure declares one
    /// file-scope function of that name at the written arity.
    ///
    /// C declares `connect` at file scope, where no namespace or class owns it,
    /// so the header that declares it is the only structured owner the callee
    /// has. The owner is that header's module identity (`sys/socket` for
    /// `<sys/socket.h>`), the identity a reviewed summary names through its
    /// target `path` (#2610). The text uses the C/C++ scope separator so the
    /// shared call-site splitter recovers exactly that pair. A C function binds
    /// no written value, so the call shape is a package function.
    #[doc(hidden)]
    pub fn c_header_function(header_module: &str, function: &str, parameter_count: u32) -> Self {
        assert!(
            !header_module.is_empty() && !header_module.contains("::"),
            "a header module identity must round-trip through the C/C++ separator: {header_module:?}"
        );
        assert!(!function.is_empty(), "a header function must be named");
        Self {
            canonical_callee: format!("{header_module}::{function}").into_boxed_str(),
            call_application: CallApplicationKind::PackageFunction,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    /// A namespace-qualified C++ call whose compile-database-scoped header
    /// closure declares one exact external function at the written arity.
    /// The namespace is part of the structured declaration identity, so it may
    /// contain nested scope components.
    #[doc(hidden)]
    pub fn cpp_header_function(namespace: &str, function: &str, parameter_count: u32) -> Self {
        assert!(!namespace.is_empty(), "a C++ namespace must be named");
        assert!(!function.is_empty(), "a C++ function must be named");
        Self {
            canonical_callee: format!("{namespace}::{function}").into_boxed_str(),
            call_application: CallApplicationKind::PackageFunction,
            dispatch_extensibility: None,
            parameter_count,
            source_jdk_artifact: None,
            python_runtime_artifact: None,
            python_model_manifest_sha256: None,
            python_formal_slots: None,
            external_member_identity: None,
        }
    }

    #[doc(hidden)]
    pub fn canonical_callee(&self) -> &str {
        &self.canonical_callee
    }

    #[doc(hidden)]
    pub fn with_source_jdk_artifact(
        mut self,
        artifact: Option<crate::analyzer::semantic_model::SemanticModelActivationEvidence>,
    ) -> Self {
        debug_assert!(
            artifact.as_ref().is_none_or(|evidence| {
                evidence.language == "java"
                    && evidence.ecosystem == "jdk"
                    && evidence.artifact_sha256.is_some()
            }),
            "only an exact prepared Java JDK can be selected as a source toolchain"
        );
        self.source_jdk_artifact = artifact;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_dispatch_extensibility(
        mut self,
        dispatch_extensibility: Option<DispatchExtensibility>,
    ) -> Self {
        self.dispatch_extensibility = dispatch_extensibility;
        self
    }

    #[doc(hidden)]
    pub fn source_jdk_artifact(
        &self,
    ) -> Option<&crate::analyzer::semantic_model::SemanticModelActivationEvidence> {
        self.source_jdk_artifact.as_ref()
    }

    #[doc(hidden)]
    pub fn python_model_manifest_sha256(&self) -> Option<&str> {
        self.python_model_manifest_sha256.as_deref()
    }

    #[doc(hidden)]
    pub fn python_runtime_artifact(
        &self,
    ) -> Option<&crate::analyzer::semantic_model::SemanticModelActivationEvidence> {
        self.python_runtime_artifact.as_ref()
    }

    #[doc(hidden)]
    pub fn python_formal_slots(
        &self,
    ) -> Option<&[crate::analyzer::lexical_definitions::FormalParameterSlot]> {
        self.python_formal_slots.as_deref()
    }

    #[doc(hidden)]
    pub const fn call_application(&self) -> CallApplicationKind {
        self.call_application
    }

    #[doc(hidden)]
    pub const fn dispatch_extensibility(&self) -> Option<DispatchExtensibility> {
        self.dispatch_extensibility
    }

    #[doc(hidden)]
    pub const fn parameter_count(&self) -> u32 {
        self.parameter_count
    }

    #[doc(hidden)]
    pub const fn has_receiver(&self) -> bool {
        matches!(self.call_application, CallApplicationKind::BoundReceiver)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[doc(hidden)]
pub enum CallApplicationKind {
    /// `p.F(args...)`: no receiver participates in the callable contract.
    PackageFunction,
    /// `v.M(args...)`: the selected method is bound to the written value.
    BoundReceiver,
    /// A receiver selection is present, but resolution did not distinguish a
    /// bound value method from a type method expression.
    ReceiverBindingUnknown,
    #[default]
    Unknown,
}

/// What one language resolver proved about a call beyond the declarations it
/// selected.
///
/// Every batch route carries this from [`resolve_one_with_evidence`] to the
/// [`CallTargetLookupOutcome`] it builds, unchanged. A resolver that proves
/// nothing leaves the default, which is the same answer the route used to
/// hard-code for every language it did not recognise. Carrying the default
/// rather than selecting the route by language is the point: a hand-kept list
/// of evidence-publishing languages discarded Ruby's boundary proof for as
/// long as Ruby was missing from it (#3459, #3496).
#[derive(Debug, Clone, Default)]
#[doc(hidden)]
pub struct CallEvidence {
    #[doc(hidden)]
    pub authority: DefinitionResolutionAuthority,
    #[doc(hidden)]
    pub call_application: CallApplicationKind,
    #[doc(hidden)]
    pub dispatch_extensibility: Option<DispatchExtensibility>,
    #[doc(hidden)]
    pub exact_external_call: Option<ExactExternalCallProof>,
    #[doc(hidden)]
    pub external_callee_identity: Option<ResolverOwnedExternalCalleeIdentity>,
}

impl CallEvidence {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn native_java_selected() -> Self {
        Self {
            authority: DefinitionResolutionAuthority::NativeJavaSelected,
            ..Self::default()
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_native_java_external_call(
        mut self,
        proof: ExactExternalCallProof,
        owner: &str,
        member: &str,
        dispatch_closed: bool,
    ) -> Self {
        let proof = proof
            .with_dispatch_extensibility(dispatch_closed.then_some(DispatchExtensibility::Closed));
        self.call_application = proof.call_application();
        self.dispatch_extensibility = proof.dispatch_extensibility();
        self.external_callee_identity = Some(ResolverOwnedExternalCalleeIdentity::new(
            Language::Java,
            owner.to_owned(),
            member.to_owned(),
        ));
        self.exact_external_call = Some(proof);
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_native_java_external_member_identity(mut self, owner: &str, member: &str) -> Self {
        self.external_callee_identity = Some(ResolverOwnedExternalCalleeIdentity::new(
            Language::Java,
            owner.to_owned(),
            member.to_owned(),
        ));
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_native_java_source_call(
        mut self,
        call_application: CallApplicationKind,
        dispatch_extensibility: Option<DispatchExtensibility>,
    ) -> Self {
        self.call_application = call_application;
        self.dispatch_extensibility = dispatch_extensibility;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const fn call_application(&self) -> CallApplicationKind {
        self.call_application
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub const fn dispatch_extensibility(&self) -> Option<DispatchExtensibility> {
        self.dispatch_extensibility
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn exact_external_call(&self) -> Option<&ExactExternalCallProof> {
        self.exact_external_call.as_ref()
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn external_callee_identity(&self) -> Option<&ResolverOwnedExternalCalleeIdentity> {
        self.external_callee_identity.as_ref()
    }
}

/// The operation that supplied a call-target lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DefinitionResolutionAuthority {
    /// The language's incumbent resolver supplied the answer.
    #[default]
    Incumbent,
    /// The selected-native operation supplied the Java source candidate.
    NativeJavaSelected,
    /// The selected-native operation supplied the Go source candidate.
    NativeGoSelected,
}

#[doc(hidden)]
pub struct DefinitionResolution {
    #[doc(hidden)]
    pub outcome: DefinitionLookupOutcome,
    #[doc(hidden)]
    pub evidence: CallEvidence,
}

impl From<DefinitionLookupOutcome> for DefinitionResolution {
    fn from(outcome: DefinitionLookupOutcome) -> Self {
        Self {
            outcome,
            evidence: CallEvidence::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionLookupStatus {
    Resolved,
    Unavailable,
    /// Resolution produced a source-backed partial answer, but the resolver
    /// could not establish an exhaustive result. This is not a proven absence
    /// and must never be projected as a precise singleton.
    ///
    /// The status is the worst thing that happened to the binding, so a
    /// definition the route did find still arrives under it: an open gap may
    /// hide a declaration that shadows the one that was found, which is why
    /// `Resolved` would overclaim. A consumer therefore reads `definitions`
    /// here too and carries the doubt through the channel it already has --
    /// `complete` on `DefinitionLookupResult`, the diagnostics array, a hover
    /// note -- instead of answering nothing. See `carries_definitions`.
    Incomplete,
    /// Resolution was stopped by an operational cancellation request.
    Cancelled,
    NoDefinition,
    UnresolvableImportBoundary,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
    /// Bounded resolution exhausted the named receiver-analysis budget before
    /// it could finish. The answer is incomplete, not a proven absence.
    ExceededBudget(ReceiverBudgetLimit),
}

impl DefinitionLookupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unavailable => "unavailable",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::NoDefinition => "no_definition",
            Self::UnresolvableImportBoundary => "unresolvable_import_boundary",
            Self::Ambiguous => "ambiguous",
            Self::UnsupportedLanguage => "unsupported_language",
            Self::InvalidLocation => "invalid_location",
            Self::NotFound => "not_found",
            Self::ExceededBudget(_) => "exceeded_budget",
        }
    }

    /// Whether an outcome with this status leaves a definition set a consumer
    /// may answer with.
    ///
    /// `Incomplete` is included deliberately; its own documentation says why.
    /// `Ambiguous` is not: an ambiguous answer has more than one winner, and
    /// a surface that wants a single target rejects it on its own terms.
    pub const fn carries_definitions(self) -> bool {
        matches!(self, Self::Resolved | Self::Incomplete)
    }
}

#[derive(Debug, Clone)]
pub struct DefinitionLookupDiagnostic {
    pub kind: String,
    pub message: String,
    /// The indexing claim this diagnostic makes, in structured form: which
    /// unit the resolver asserts is outside the workspace, and in which role.
    /// `None` for diagnostics that make no indexing claim. Lets contract
    /// consumers (the MCP property fuzzer's I4) test the claim without
    /// parsing `message`.
    pub claim: Option<UnindexedClaim>,
}

/// The indexing claim a failure diagnostic makes, in structured form.
/// `subject` is the resolver's fully-qualified intent where one exists (the
/// Java static-import site passes `butterknife.lint`, not the backticked
/// `lint` the message shows); `role` names the kind of unit the subject was
/// resolved as, which is the search bucket a contradicting in-workspace hit
/// must come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnindexedClaim {
    pub kind: UnindexedClaimKind,
    /// The units the claim is about, exactly as the resolver means them (a
    /// fully-qualified import path where one exists, e.g. `butterknife.lint`,
    /// not the backticked terminal the message shows). Several entries when
    /// one message claims a list (Go dot-imported packages).
    pub subjects: Vec<String>,
    pub role: ClaimSubjectRole,
}

/// What a failure claim asserts about indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnindexedClaimKind {
    /// The subject itself is asserted to be outside the indexed workspace
    /// (an import/include/using/crate boundary).
    ExternalBoundary,
    /// The name resolved to an external declaration (a builtin, an external
    /// package's member); the workspace is not claimed to lack a declaration
    /// of the name, so only an identity-exact in-workspace hit contradicts.
    ResolvedExternal,
    /// The resolver admits ignorance: the name may be declared by an owner
    /// the workspace does not index (a supertype/base type). Any in-workspace
    /// declaration of the name contradicts the claim.
    UnindexedOwner,
}

/// The kind of unit a claim's subject was resolved as, named after the search
/// bucket a contradicting in-workspace hit must come from. `Any` keeps the
/// caller's prior behavior (a site whose subject could be more than one kind
/// passes this, so an unsure site changes nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSubjectRole {
    Module,
    Type,
    Member,
    Any,
}

impl UnindexedClaim {
    /// The subject itself is asserted to be outside the indexed workspace.
    pub fn external_boundary(subject: impl Into<String>, role: ClaimSubjectRole) -> Self {
        Self::external_boundary_many(vec![subject.into()], role)
    }

    /// The multi-subject form (one message claiming a list of externals).
    pub fn external_boundary_many<S: AsRef<str>>(
        subjects: impl IntoIterator<Item = S>,
        role: ClaimSubjectRole,
    ) -> Self {
        Self {
            kind: UnindexedClaimKind::ExternalBoundary,
            subjects: subjects
                .into_iter()
                .map(|subject| subject.as_ref().to_string())
                .collect(),
            role,
        }
    }

    /// The name resolved to an external declaration (a builtin, an external
    /// package's member); the workspace is not claimed to lack the name.
    pub fn resolved_external(subject: impl Into<String>, role: ClaimSubjectRole) -> Self {
        Self {
            kind: UnindexedClaimKind::ResolvedExternal,
            subjects: vec![subject.into()],
            role,
        }
    }

    /// The resolver admits ignorance: the name may be declared by an owner
    /// the workspace does not index (a supertype/base type).
    pub fn unindexed_owner(subject: impl Into<String>, role: ClaimSubjectRole) -> Self {
        Self {
            kind: UnindexedClaimKind::UnindexedOwner,
            subjects: vec![subject.into()],
            role,
        }
    }
}

/// Historical forward evidence that stopped at an indexed selector prefix.
/// New resolvers must not emit this for an exact focused token, but the
/// differential checker still recognizes recorded outcomes carrying it.
pub const PARTIAL_SELECTOR_CHAIN_DIAGNOSTIC_KIND: &str = "partial_selector_chain";

/// The name binds to a local binder -- a `case` pattern binding, a block-local
/// `val`/`def`, a parameter -- which no analyzer publishes as a CodeUnit.
pub const LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND: &str = "local_variable_reference";

/// The name resolves to a language-provided predeclared symbol, such as Go's
/// `error`, `len`, or `append`, rather than a declaration in the workspace.
pub const PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND: &str = "predeclared_symbol_reference";

/// The site is a declaration or import occurrence, not a reference, so there is
/// no definition for it to reach.
pub const DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND: &str = "declaration_or_import_site";

/// A complete Go package and dot-import scope contains no declaration for an
/// unqualified call name.
pub const GO_UNQUALIFIED_CALL_NO_TARGET_DIAGNOSTIC_KIND: &str = "go_unqualified_call_no_target";

/// Positive Go declaration facts prove that the selected package name is not
/// one public function applicable to this ordinary argument list.
pub const GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND: &str =
    "go_modeled_package_call_not_applicable";

/// A Go declaration model mentions the selected package name, but conflicts
/// or missing call-shape facts prevent a positive or negative callable proof.
pub const GO_MODELED_PACKAGE_CALL_UNPROVEN_DIAGNOSTIC_KIND: &str =
    "go_modeled_package_call_unproven";

/// A `macro_rules!` matcher was found but no arm consumed the invocation.
pub const MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND: &str = "macro_matcher_failed";

/// Two matcher arms or two indexed macros bound the focused token differently.
pub const MACRO_MATCHER_DISAGREEMENT_DIAGNOSTIC_KIND: &str = "macro_matcher_disagreement";

/// The selected matcher fragment carries no namespace (`tt`, `meta`, `vis`,
/// `lifetime`, `literal`, or an `ident` whose transcriber role is mixed).
pub const MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND: &str = "macro_fragment_no_namespace";

/// Successful matcher binding evidence for census grading.
pub const MACRO_MATCHER_BINDING_DIAGNOSTIC_KIND: &str = "macro_matcher_binding";

/// The matcher bound the focused token to a declaration-position fragment, so
/// the token denotes itself and there is nothing else to reach.
///
/// This is the half of `macro_matcher_binding` that is an answer. The other
/// half is [`MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND`], which is the
/// matcher saying it does not know, and the two must not share a kind: a
/// consumer that reads one kind cannot tell a decided declaration from an
/// undecided token tree.
pub const MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND: &str = "macro_matcher_declaration";

/// Whether a diagnostic kind carries an ADJUDICATED answer: the resolver
/// identified what the site is and answered it, rather than failing to reach a
/// target it was looking for.
///
/// That distinction is what separates an answer from joint blindness, and any
/// consumer that grades forward misses must honour it. The status alone cannot:
/// [`DefinitionLookupStatus::NoDefinition`] carries both "the target exists and
/// I could not reach it" and "there is no target to reach, and here is why".
/// [`DefinitionLookupStatus::UnresolvableImportBoundary`] says it in the status;
/// the kinds here say it in the diagnostic, because the resolver PROVED the name
/// binds to something the declaration index deliberately does not publish
/// (#1858).
/// The focused Rust wildcard, inferred type, or unnamed alias has no
/// declaration to reach.
pub const RUST_NON_REFERENCE_SYNTAX_DIAGNOSTIC_KIND: &str = "rust_non_reference_syntax";

/// The focused token is an explicit `crate` path anchor, which is syntax and
/// not a reference to any declaration.
pub const RUST_CRATE_ANCHOR_DIAGNOSTIC_KIND: &str = "crate_anchor";

/// The selected Rust `cfg` predicate over the focused declaration is refuted,
/// so the declaration is not in this build at all.
pub const RUST_INACTIVE_CFG_DIAGNOSTIC_KIND: &str = "inactive_cfg";

/// The selected Rust binding was complete and named no source-backed
/// definition.
pub const RUST_NO_INDEXED_DEFINITION_DIAGNOSTIC_KIND: &str = "no_indexed_definition";

/// The selected Rust binding's only incompleteness is an open boundary at a
/// declared dependency nothing indexed, which is itself the boundary claim.
pub const RUST_UNINDEXED_IMPORT_BOUNDARY_DIAGNOSTIC_KIND: &str = "unindexed_import_boundary";

/// The selected Rust route reached a source-declared macro or attribute
/// surface whose generated items this analyzer does not expand.
pub const RUST_UNSUPPORTED_GENERATED_SURFACE_BOUNDARY_DIAGNOSTIC_KIND: &str =
    "unsupported_generated_surface_boundary";

/// The selected Rust type answer was typed-complete, examined at least one
/// projected answer, and named no type.
///
/// This is the type route's analogue of
/// [`RUST_NO_INDEXED_DEFINITION_DIAGNOSTIC_KIND`]. The entitlement is the same
/// shape -- `typed_complete` and `projected_answers > 0` -- and the kind is
/// what makes it visible from outside `adapt_type_answer`, so the
/// decided-negative guard can cover `TypeLookupStatus::NoType`.
pub const RUST_NO_TYPED_PROJECTION_DIAGNOSTIC_KIND: &str = "no_typed_projection";

/// A Rust path head that names a crate this workspace compiles, by its extern
/// name or through an alias of its root. A crate root has no declaration, so
/// the answer is `no_definition`, and the diagnostic names the crate.
pub const RUST_WORKSPACE_CRATE_NAMESPACE_DIAGNOSTIC_KIND: &str = "workspace_crate_namespace";

/// A decided negative reached a consumer without proving the world it claims,
/// and was answered as the honest incompleteness instead.
pub const UNPROVED_CLOSED_WORLD_DIAGNOSTIC_KIND: &str = "unproved_closed_world";

/// Why a Rust answer is entitled to publish a decided negative.
///
/// A decided negative -- [`DefinitionLookupStatus::NoDefinition`] or
/// [`DefinitionLookupStatus::UnresolvableImportBoundary`] -- is a claim about a
/// whole world: "I looked everywhere this name could have been declared, and it
/// is not there." For a tree-sitter language that world is the workspace
/// declaration index, which is complete by construction, and the load-bearing
/// second question is answered structurally by [`gated_boundary`]. For Rust the
/// world is the query's SELECTION, which can be partial, so the claim needs
/// either `ResolutionCompletion::Complete` on the answer or a reason the
/// selection was never the question.
///
/// Five of the 2026-09-16 census triage's wrong-answer groups are one shape: a
/// Rust route answered a decided negative on a path that had proved neither.
/// `DefinitionLookupStatus::Incomplete` carrying the reason was available at
/// every one of them, and a consumer already knows how to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustClosedWorld {
    /// The focused range does not denote a reference at all, and the retained
    /// AST says so. No selection was consulted, so none can be demanded.
    NotAReference,
    /// The resolver identified what the focused name binds to and answered it,
    /// rather than failing to reach a target it was looking for.
    Adjudicated,
    /// Persisted Cargo topology proves this source module is excluded by the
    /// selected cfg/feature world.
    InactiveSelection,
    /// The resolution engine finished this reference's whole selection.
    SelectionComplete,
    /// The selection finished at a declared dependency nothing indexed. That
    /// completion is itself the boundary claim, and nothing weaker is.
    ProvedExternalBoundary,
    /// The selected source names a structured macro or attribute boundary the
    /// analyzer does not expand; this is an explicit unsupported surface.
    UnsupportedSurface,
}

/// The closed world a Rust point-route diagnostic kind proves, if it proves
/// one.
///
/// This registry is the rule, not a lookup table of convenience.
/// [`hold_rust_answer_to_its_proof`] answers any decided negative whose
/// diagnostics name no entry here as the honest incompleteness instead, so a
/// new Rust emission site fails CLOSED: it publishes doubt, never a claim it
/// has not earned. A site that IS entitled to the claim records the entitlement
/// here, once, where a reader can check it against the code that emits the
/// kind.
///
/// Every entry is earned. `macro_matcher_binding` used to cover two different
/// findings under one kind and one message, and its entry was the one the
/// decided-negative audit marked UNEARNED. `rust::native_points` now splits
/// them: a token the matcher bound to a declaration position is
/// [`MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND`], which is adjudicated and is
/// registered below, and a token whose fragment carries no namespace at all
/// (`tt`, `meta`, `vis`, `lifetime`, `literal`, or an `ident` whose transcriber
/// role is mixed, unused or undetermined --
/// `brokk_bifrost_rust::macro_matcher`) is
/// [`MACRO_FRAGMENT_NO_NAMESPACE_DIAGNOSTIC_KIND`], which is the matcher saying
/// it could not decide and answers `Incomplete` on its own. That kind is
/// deliberately absent from this registry and from
/// [`is_adjudicated_answer_diagnostic_kind`].
pub fn rust_closed_world_for_diagnostic_kind(kind: &str) -> Option<RustClosedWorld> {
    match kind {
        RUST_NON_REFERENCE_SYNTAX_DIAGNOSTIC_KIND | RUST_CRATE_ANCHOR_DIAGNOSTIC_KIND => {
            Some(RustClosedWorld::NotAReference)
        }
        RUST_INACTIVE_CFG_DIAGNOSTIC_KIND => Some(RustClosedWorld::InactiveSelection),
        "InactiveCfgPlacement" => Some(RustClosedWorld::InactiveSelection),
        MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND
        | MACRO_MATCHER_DECLARATION_DIAGNOSTIC_KIND
        // Rust emits this kind from one site only: a focused `lifetime` node
        // in the retained AST (`rust::native_points`). The token binds to the
        // lifetime binder the route named, which is what `Adjudicated` means,
        // and the binder is never a CodeUnit in any language.
        | LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND
        // `rust::native_points::claim_external_route_head` emits it for a path
        // head the crate rows bind to a workspace crate's root: the resolver
        // named what the head binds, and a crate root is never a CodeUnit.
        | RUST_WORKSPACE_CRATE_NAMESPACE_DIAGNOSTIC_KIND => Some(RustClosedWorld::Adjudicated),
        RUST_NO_INDEXED_DEFINITION_DIAGNOSTIC_KIND | RUST_NO_TYPED_PROJECTION_DIAGNOSTIC_KIND => {
            Some(RustClosedWorld::SelectionComplete)
        }
        RUST_UNINDEXED_IMPORT_BOUNDARY_DIAGNOSTIC_KIND => {
            Some(RustClosedWorld::ProvedExternalBoundary)
        }
        RUST_UNSUPPORTED_GENERATED_SURFACE_BOUNDARY_DIAGNOSTIC_KIND => {
            Some(RustClosedWorld::UnsupportedSurface)
        }
        _ => None,
    }
}

/// Hold one Rust point answer to the decided-negative rule on its way out of
/// the language dispatch.
///
/// Every Rust definition, declaration, and navigation answer passes through
/// this function exactly once, so the rule cannot be bypassed by adding an
/// emission site: an unproved decided negative becomes
/// [`DefinitionLookupStatus::Incomplete`] with the claim it tried to make and
/// the diagnostics it carried, which is what the route should have answered.
///
/// The downgrade is deliberately not an assertion. A missing entitlement is a
/// gap a lane can introduce, not a state that cannot occur, and the answer a
/// consumer needs in that case is doubt, not a panic.
#[doc(hidden)]
pub fn hold_rust_answer_to_its_proof(
    mut outcome: DefinitionLookupOutcome,
) -> DefinitionLookupOutcome {
    let claimed = match outcome.status {
        DefinitionLookupStatus::NoDefinition
        | DefinitionLookupStatus::UnresolvableImportBoundary => outcome.status,
        _ => return outcome,
    };
    if outcome
        .diagnostics
        .iter()
        .any(|diagnostic| rust_closed_world_for_diagnostic_kind(&diagnostic.kind).is_some())
    {
        return outcome;
    }
    let carried = format!("{:?}", outcome.diagnostics);
    outcome.status = DefinitionLookupStatus::Incomplete;
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        claim: None,
        kind: UNPROVED_CLOSED_WORLD_DIAGNOSTIC_KIND.to_string(),
        message: format!(
            "the selected Rust route answered `{}` without proving the selection that claim is about; carried diagnostics: {carried}",
            claimed.as_str()
        ),
    });
    outcome
}

pub fn is_adjudicated_answer_diagnostic_kind(kind: &str) -> bool {
    matches!(
        kind,
        LOCAL_VARIABLE_REFERENCE_DIAGNOSTIC_KIND
            | PREDECLARED_SYMBOL_REFERENCE_DIAGNOSTIC_KIND
            | DECLARATION_OR_IMPORT_SITE_DIAGNOSTIC_KIND
            | GO_MODELED_PACKAGE_CALL_NOT_APPLICABLE_DIAGNOSTIC_KIND
            | MACRO_MATCHER_FAILED_DIAGNOSTIC_KIND
            | MACRO_MATCHER_DISAGREEMENT_DIAGNOSTIC_KIND
    )
}

fn with_definition_batch_context<T>(
    analyzer: &dyn IAnalyzer,
    resolve: impl for<'a> FnOnce(&'a dyn IAnalyzer, &mut DefinitionBatchContext<'a, '_>) -> T,
) -> T {
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    resolve(analyzer, &mut context)
}

#[doc(hidden)]
pub fn resolve_definition_batch(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
) -> Vec<DefinitionLookupOutcome> {
    let _scope = profiling::scope("get_definition::resolve_definition_batch");
    if profiling::enabled() {
        profiling::note(format!("request_count={}", requests.len()));
    }
    with_definition_batch_context(analyzer, |analyzer, context| {
        resolve_definition_requests(analyzer, token, context, requests, None, None)
    })
}

#[doc(hidden)]
pub fn resolve_navigation_batch(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
    operation: NavigationOperation,
    cancellation: Option<&CancellationToken>,
) -> Vec<NavigationLookupOutcome> {
    let _scope = profiling::scope("get_definition::resolve_navigation_batch");
    if profiling::enabled() {
        profiling::note(format!(
            "request_count={}, operation={operation:?}",
            requests.len()
        ));
    }
    with_definition_batch_context(analyzer, |analyzer, context| {
        resolve_navigation_requests(analyzer, token, context, requests, operation, cancellation)
    })
}

fn resolve_navigation_requests<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    requests: Vec<DefinitionLookupRequest>,
    operation: NavigationOperation,
    cancellation: Option<&CancellationToken>,
) -> Vec<NavigationLookupOutcome> {
    let languages: Vec<_> = requests
        .iter()
        .map(|request| language_for_file(&request.file))
        .collect();
    // The reference file each outcome answers for. C++ navigation needs it to
    // build the visibility index its identity comparisons read, and the
    // requests are consumed by the resolution below.
    let reference_files: Vec<_> = requests
        .iter()
        .map(|request| request.file.clone())
        .collect();
    let resolutions = resolve_definition_resolutions(
        analyzer,
        token,
        context,
        requests,
        cancellation,
        Some(operation),
        None,
        &mut Vec::new(),
    );
    languages
        .into_iter()
        .zip(reference_files)
        .zip(resolutions)
        .map(|((language, reference_file), resolution)| {
            navigation_lookup_outcome(
                analyzer,
                token,
                context,
                &reference_file,
                resolution,
                language,
                operation,
            )
        })
        .collect()
}

/// Optional per-batch resolver supplied by the language. Its operation and
/// factory remain owned by that language for the duration of this query.
#[doc(hidden)]
pub trait DefinitionBatchResolver<'a> {
    /// Extend this batch's existing operation to its enclosing dispatch file window.
    fn retain_file_operation(&mut self) {}

    /// Release reader-backed operation state before a caller needs store writes.
    fn release_file_operation(&mut self) {}

    /// Conservative boundary before generic analysis may check out store reads.
    fn release_before_store_read(&mut self) {
        self.release_file_operation();
    }

    fn precompute(
        &mut self,
        analyzer: &dyn IAnalyzer,
        context: &mut DefinitionBatchContext<'_, '_>,
        requests: &[DefinitionLookupRequest],
        cancellation: Option<&CancellationToken>,
    );

    #[allow(clippy::too_many_arguments)]
    fn resolve_definition_dispatch(
        &mut self,
        analyzer: &'a dyn IAnalyzer,
        token: QueryToken<'_>,
        context: &mut DefinitionBatchContext<'a, '_>,
        request: &DefinitionLookupRequest,
        source: &Arc<str>,
        tree: &Option<Tree>,
        site: &ResolvedReferenceSite,
        operation: Option<NavigationOperation>,
        cancellation: Option<&CancellationToken>,
        go_session: Option<&ResolutionSession>,
    ) -> std::ops::ControlFlow<DefinitionResolution, DefinitionResolution>;
}

/// Resolve one batch of requests for callers that need only the declarations.
///
/// The batch driver keeps each resolver's [`CallEvidence`]; a caller that
/// answers a definition question has no use for it and drops it here. A
/// caller that answers a *call* question keeps it, so that no route has to
/// know which languages publish evidence.
#[doc(hidden)]
pub fn resolve_definition_requests<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
    operation: Option<NavigationOperation>,
) -> Vec<DefinitionLookupOutcome> {
    resolve_definition_resolutions(
        analyzer,
        token,
        context,
        requests,
        cancellation,
        operation,
        None,
        &mut Vec::new(),
    )
    .into_iter()
    .map(|resolution| resolution.outcome)
    .collect()
}

/// Record what every request in one batch probes, before any of them runs.
///
/// The entry is the only place a batch can name its inputs unconditionally.
/// A resolver that reaches a declaration names its own reads on the way, but
/// one that reaches nothing -- an import specifier that named no file, a
/// receiver with no proven type, a name in no visible scope -- returns before
/// any funnel runs, and a memoized answer skips the funnel a second time. So
/// every request names its speculative keys here before it resolves.
#[doc(hidden)]
pub fn record_definition_batch_probe_reads(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_, '_>,
    requests: &[DefinitionLookupRequest],
) {
    if !analyzer.read_ledger_attached() {
        return;
    }
    let _scope = profiling::scope("get_definition::record_batch_probe_reads");
    for request in requests {
        let language = language_for_file(&request.file);
        if language == Language::None {
            continue;
        }
        let source = match context.source(&request.file) {
            Ok(source) => source,
            // The request's own file is not there to resolve in. That is a
            // negative answer about one path, and a head that has the path
            // answers differently, so the reader names the path rather than
            // staying silent about it.
            Err(_) => {
                analyzer.record_read(ReadKey::path_absent(
                    language,
                    rel_path_string(&request.file).as_str(),
                ));
                continue;
            }
        };
        let tree = context.tree(&request.file, language, &source);
        // An unresolvable location is an answer about this file's own bytes,
        // which the reader that produced the request already named.
        if let Ok(site) = focused_reference_site(context, request, language, &source, tree.as_ref())
        {
            record_definition_probe_reads(analyzer, language, &site, &source);
        }
    }
}

/// Publish the precise inputs of one successful definition request.
///
/// Shared declaration readers already publish their exact answers while hiding
/// hydration. All remaining resolver reads stay dependencies: they can supply
/// imports, re-exports, incomplete metadata, or other context that the selected
/// declarations do not encode. A request that resolves nothing also retains
/// every speculative probe to detect a declaration added later.
fn publish_definition_reads(
    analyzer: &dyn IAnalyzer,
    outcome: &DefinitionLookupOutcome,
    mut reads: Vec<ReadKey>,
) {
    if outcome.definitions.is_empty() {
        for read in reads {
            analyzer.record_read(read);
        }
        return;
    }

    let (_, declaration_reads) =
        crate::analyzer::i_analyzer::capture_nested_reads(analyzer, || {
            let indexes = analyzer.workspace_fact_indexes();
            for declaration in &outcome.definitions {
                if let Some(index) = indexes
                    .iter()
                    .find(|index| index.fact_index_language() == declaration.source().language())
                {
                    index.declaration_facts_digest(declaration);
                }
            }
        });
    reads.extend(declaration_reads);

    for read in reads {
        analyzer.record_read(read);
    }
}

/// Record the index keys one definition request probes, whatever answer the
/// resolution reaches.
///
/// A resolution that finds a declaration records its own probes: every store
/// funnel names the index key it read, so its read set is already exact. A
/// resolution that finds nothing often records nothing at all, because it
/// returns before any funnel runs -- the import specifier named no file, the
/// receiver had no proven type, the name was in no visible scope. That
/// negative answer still depends on the workspace: a file added later that
/// declares the name would answer it, and a read set that stayed silent would
/// let the unit be reused where the name now resolves. So the request names
/// the keys the funnels would have named, at the site, before the language
/// resolvers can return.
///
/// Two spellings are named, because a request may focus any segment of a
/// qualified reference (`qualified_paths` builds one request per segment):
/// the focused token, which is the identifier every declaration of that name
/// publishes, and the whole reference expression, which is the exact
/// qualified name an exact-name probe uses. A declaration added anywhere
/// under either spelling is in the changed-key set, and it is spelled there
/// by the store's own row builders, which is why the bytes here are the
/// site's own text and the adapter's own normalization of it rather than any
/// second interpretation.
///
/// One seek cannot be named exactly. A language whose index stores decorated
/// identifiers as a *prefix* range rather than as keys (C# generic arity)
/// probes that range, and exact-key membership can verify no range, so such a
/// request records the whole-language scope -- the same coarse, honest key
/// the identifier funnel itself records for that seek.
///
/// Recording at the site over-records for a reference that turns out to be a
/// parameter or a local, whose answer is a function of its own file. That is
/// the sound direction: naming an input the request did not read costs reuse,
/// while learning that it was a local only after the resolver ran would mean
/// recording behind the early return this exists to get in front of.
fn record_definition_probe_reads(
    analyzer: &dyn IAnalyzer,
    language: Language,
    site: &ResolvedReferenceSite,
    source: &str,
) {
    if !analyzer.read_ledger_attached() {
        return;
    }
    debug_assert!(
        source
            .get(site.focus_start_byte..site.focus_end_byte)
            .is_some(),
        "a reference site's focus is a range of the source it was resolved in"
    );
    let identifier = source
        .get(site.focus_start_byte..site.focus_end_byte)
        .unwrap_or(site.text.as_str());
    analyzer.record_read(ReadKey::index(
        IndexFamily::DefinitionIdentifier,
        identifier,
    ));
    analyzer.record_read(ReadKey::index(IndexFamily::DefinitionExact, &site.text));
    let normalized = language_support_for_hook(language, "forward_query_provider")
        .and_then(|support| support.forward_query_provider(analyzer))
        .map_or_else(
            || site.text.clone(),
            |provider| provider.normalize_rendered_name(&site.text),
        );
    analyzer.record_read(ReadKey::index(
        IndexFamily::DefinitionNormalizedTail,
        normalized,
    ));
    for seek in decorated_identifier_seeks(language, identifier) {
        match seek {
            IdentifierSeek::Exact(spelling) => {
                analyzer.record_read(ReadKey::index(IndexFamily::DefinitionIdentifier, spelling))
            }
            IdentifierSeek::Prefix(_) => {
                analyzer.record_read(analyzer.workspace_scope_read_key(&[language]))
            }
        }
    }
}

/// Resolve one batch of requests, keeping each resolver's own call evidence
/// and optionally draining the resolution trace after each one.
///
/// Definition, navigation, and traced batches run through here. The evidence
/// travels with the resolution the whole way, so a route that answers a call
/// -- C/C++ call targets reach one through [`resolve_navigation_requests`] --
/// never has to decide in advance which languages publish any (#3496).
///
/// `trace_session` and `traces` travel together and are `None`/empty for every
/// caller but [`trace::resolve_definition_batch_with_trace`]. They are
/// parameters rather than context state because the drain must happen exactly
/// at the per-request boundary, which is here and nowhere else: the recorder is
/// append-only, so without a drain point every request would inherit the rows
/// of the ones before it.
#[allow(clippy::too_many_arguments)]
fn resolve_definition_resolutions<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
    operation: Option<NavigationOperation>,
    trace_session: Option<&trace::TraceSession>,
    traces: &mut Vec<(Vec<TraceCandidate>, Option<trace::TraceCompleteness>)>,
) -> Vec<DefinitionResolution> {
    let _query_scope = cancellation.map_or_else(
        || AnalyzerQueryScope::new(analyzer),
        |cancellation| AnalyzerQueryScope::with_cancellation(analyzer, cancellation),
    );
    let mut remaining_file_requests: HashMap<ProjectFile, usize> = HashMap::default();
    for request in &requests {
        *remaining_file_requests
            .entry(request.file.clone())
            .or_default() += 1;
    }

    let reusable_definition_batch = trace_session.is_none()
        && operation.is_none()
        && requests.len() > 1
        && requests
            .first()
            .is_some_and(|first| requests.iter().all(|request| request.file == first.file));
    let mut definition_batch = reusable_definition_batch
        .then(|| {
            language_support_for_hook(
                language_for_file(&requests[0].file),
                "definition_batch_resolver",
            )
            .and_then(|support| support.definition_batch_resolver(analyzer, cancellation))
        })
        .flatten();

    requests
        .into_iter()
        .map(|request| {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                if let Some(session) = trace_session {
                    traces.push(session.take_request_trace());
                }
                return cancelled(
                    "definition resolution was cancelled before this request completed",
                )
                .into();
            }
            let language = language_for_file(&request.file);
            let file = request.file.clone();
            let probes = if analyzer.read_ledger_attached() {
                crate::analyzer::i_analyzer::capture_nested_reads(analyzer, || {
                    record_definition_batch_probe_reads(
                        analyzer,
                        context,
                        std::slice::from_ref(&request),
                    );
                })
                .1
            } else {
                Vec::new()
            };
            let resolve = || {
                resolve_one_with_evidence(
                    analyzer,
                    token,
                    context,
                    request,
                    operation,
                    cancellation,
                    None,
                    definition_batch
                        .as_mut()
                        .map(|batch| batch.as_mut() as &mut dyn DefinitionBatchResolver<'a>),
                )
            };
            let resolution = if analyzer.read_ledger_attached() {
                let (resolution, mut reads) =
                    crate::analyzer::i_analyzer::capture_nested_reads(analyzer, resolve);
                // Only the speculative site probes are subsumed by a
                // successful resolution. Preserve every actual resolver read.
                reads.extend(probes.into_iter().filter(|read| {
                    resolution.outcome.definitions.is_empty()
                        || !matches!(read, ReadKey::Index { .. } | ReadKey::Scope { .. })
                }));
                publish_definition_reads(analyzer, &resolution.outcome, reads);
                resolution
            } else {
                resolve()
            };
            if let Some(remaining) = remaining_file_requests.get_mut(&file) {
                *remaining -= 1;
                if *remaining == 0
                    && let Some(support) =
                        language_support_for_hook(language, "release_definition_file")
                {
                    support.release_definition_file(context, &file);
                }
            }
            if let Some(session) = trace_session {
                traces.push(session.take_request_trace());
            }
            resolution
        })
        .collect()
}

pub fn resolve_definition_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
) -> Vec<DefinitionLookupOutcome> {
    // Recorded per analyzer instance through the test-hook counter on
    // `analyzer` itself, rather than a process-wide static: a static here was
    // inflated by any other test calling this function concurrently (#3010).
    // A batching caller asserts this collapsed many per-edge calls into one
    // call per file rather than re-deriving that from timing (bifrost#15).
    #[cfg(test)]
    analyzer
        .test_hooks()
        .record_resolve_definition_batch_with_source_call_for_test();
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = definition_batch_context_with_source(analyzer, scope.token(), file, source);
    resolve_definition_requests(analyzer, token, &mut context, requests, None, None)
}

/// Preserve incumbent deferred-site authority for the legacy usage graph.
#[doc(hidden)]
pub fn resolve_legacy_usage_graph_definition_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
) -> Vec<DefinitionLookupOutcome> {
    // Recorded per analyzer instance through the test-hook counter on
    // `analyzer` itself, rather than a process-wide static: a static here was
    // inflated by any other test calling this function concurrently (#3010).
    // A batching caller asserts this collapsed many per-edge calls into one
    // call per file rather than re-deriving that from timing (bifrost#15).
    #[cfg(test)]
    analyzer
        .test_hooks()
        .record_resolve_definition_batch_with_source_call_for_test();
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = definition_batch_context_with_source(analyzer, scope.token(), file, source);
    context.route = DefinitionBatchRoute::LegacyUsageGraph;
    resolve_definition_requests(analyzer, token, &mut context, requests, None, None)
}

fn definition_batch_context_with_source<'a, 'token>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'token>,
    file: ProjectFile,
    source: Arc<str>,
) -> DefinitionBatchContext<'a, 'token> {
    let mut context = DefinitionBatchContext::new(analyzer, token);
    context.sources.insert(file, Ok(source));
    context
}

pub fn resolve_value_identity_with_source(
    analyzer: &dyn IAnalyzer,
    request: DefinitionLookupRequest,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: Option<&CancellationToken>,
) -> Option<ResolvedValueIdentity> {
    let outcome = if let Some(cancellation) = cancellation {
        resolve_definition_batch_with_source_and_cancellation(
            analyzer,
            vec![request.clone()],
            file.clone(),
            Arc::clone(&source),
            cancellation,
        )
    } else {
        resolve_definition_batch_with_source(
            analyzer,
            vec![request.clone()],
            file.clone(),
            Arc::clone(&source),
        )
    }
    .into_iter()
    .next()?;
    if outcome.status == DefinitionLookupStatus::Resolved {
        let mut definitions = outcome.definitions;
        definitions.sort_by_key(|definition| definition.declaration_id());
        definitions.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
        let mut modeled = outcome.modeled_definitions;
        modeled.sort_by(|left, right| left.id.cmp(&right.id));
        modeled.dedup_by(|left, right| left.id == right.id);
        let resolved = match (definitions.as_slice(), modeled.as_slice()) {
            ([definition], []) => Some(ResolvedValueIdentity {
                kind: ResolvedValueIdentityKind::WorkspaceDeclaration,
                identity: definition.declaration_id().to_string(),
                aliases: Vec::new(),
            }),
            ([], [symbol]) if exact_semantic_model_value_identity(symbol) => {
                Some(ResolvedValueIdentity {
                    kind: ResolvedValueIdentityKind::ActiveSemanticModel,
                    identity: symbol.id.clone(),
                    aliases: symbol.aliases.clone(),
                })
            }
            _ => None,
        };
        if resolved.is_some() {
            return resolved;
        }
        return language_support_for_hook(language_for_file(&file), "definition_value_identity")?
            .definition_value_identity(analyzer, &request, &file, &source, cancellation);
    }

    if outcome.status == DefinitionLookupStatus::InvalidLocation {
        return language_support_for_hook(language_for_file(&file), "definition_value_identity")?
            .definition_value_identity(analyzer, &request, &file, &source, cancellation);
    }

    if outcome.status != DefinitionLookupStatus::UnresolvableImportBoundary
        || !matches!(
            crate::analyzer::common::language_for_file(&file),
            Language::Python | Language::CSharp
        )
    {
        return None;
    }
    if crate::analyzer::common::language_for_file(&file) == Language::CSharp {
        let reference = outcome.reference.as_ref()?.text.as_str();
        let overlay = analyzer.semantic_model_overlay()?;
        let matched = overlay.symbols_named(reference);
        let [symbol] = matched.records.as_slice() else {
            return None;
        };
        if matched.disposition
            != crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
            || symbol.owner_id.is_none()
            || symbol.language != Language::CSharp.config_label()
            || symbol.qualified_name != reference
            || symbol.provenance.ambiguous
            || symbol.provenance.completeness
                != crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
        {
            return None;
        }
        return Some(ResolvedValueIdentity {
            kind: ResolvedValueIdentityKind::ActiveSemanticModel,
            identity: symbol.id.clone(),
            aliases: symbol.aliases.clone(),
        });
    }
    language_support_for_hook(language_for_file(&file), "definition_value_identity")?
        .definition_value_identity(analyzer, &request, &file, &source, cancellation)
}

#[doc(hidden)]
pub fn exact_semantic_model_value_identity(
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> bool {
    !symbol.provenance.ambiguous
        && (symbol.provenance.completeness
            == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete
            || matches!(
                symbol.kind,
                crate::analyzer::semantic_model::SemanticModelSymbolKind::Field
                    | crate::analyzer::semantic_model::SemanticModelSymbolKind::Property
            ))
}

/// Resolve explicit target-token requests without allowing a language resolver
/// to substitute a neighboring token from the expanded reference expression.
/// The context-reference tool is the sole caller because its `target` field is
/// an exact-token contract; location, differential, rename, and inverse scans
/// retain their established point-navigation semantics.
#[doc(hidden)]
pub fn resolve_definition_batch_with_source_exact_token_focus(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: Option<&CancellationToken>,
) -> Vec<DefinitionLookupOutcome> {
    let scope = cancellation.map_or_else(
        || AnalyzerQueryScope::new(analyzer),
        |cancellation| AnalyzerQueryScope::with_cancellation(analyzer, cancellation),
    );
    let token = scope.token();
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    context.exact_token_focus = true;
    context.sources.insert(file, Ok(source));
    resolve_definition_requests(analyzer, token, &mut context, requests, cancellation, None)
}

/// The traced counterpart of [`resolve_definition_batch_with_source`]: same
/// inputs and the same resolver decisions, plus one [`ResolutionTraceResult`]
/// per request. Probe callers (external-boundary auditing) have no
/// cancellation source of their own, so this wraps
/// [`trace::resolve_definition_batch_with_trace`] with a token that never
/// cancels, matching the untraced entry point's unconditional-completion
/// contract.
pub fn resolve_definition_batch_with_source_traced(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
) -> Vec<(DefinitionLookupOutcome, ResolutionTraceResult)> {
    resolve_definition_batch_with_trace(analyzer, requests, file, source, &CancellationToken::new())
}

pub fn resolve_navigation_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    operation: NavigationOperation,
) -> Vec<NavigationLookupOutcome> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = definition_batch_context_with_source(analyzer, scope.token(), file, source);
    resolve_navigation_requests(analyzer, token, &mut context, requests, operation, None)
}

pub fn navigation_declaration_site_targets(
    analyzer: &dyn IAnalyzer,
    candidate: CodeUnit,
    operation: NavigationOperation,
) -> Vec<NavigationTarget> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    match language_support_for_hook(
        language_for_file(candidate.source()),
        "definition_declaration_site_targets",
    ) {
        Some(support) => {
            support.definition_declaration_site_targets(analyzer, token, candidate, operation)
        }
        None => vec![NavigationTarget {
            code_unit: candidate,
            declaration_range: None,
        }],
    }
}

/// Whether the allocation expression at `offset` binds its result by
/// reference (`Some(true)`) or creates an inline value (`Some(false)`).
///
/// `None` means that the source does not contain one of the exact structured
/// Go forms supported by the producer, or that a named type's declaration is
/// unavailable or ambiguous. The caller must hold a semantic Allocation row
/// at this offset: the producer has already established that `new` or `make`
/// denotes the builtin, rather than a shadowing callable.
pub fn allocation_binds_by_reference_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "allocation_binds_by_reference_at_offset",
    )
    .and_then(|support| support.allocation_binds_by_reference_at_offset(file, source, offset))
}

/// Whether the allocation expression at `offset` boxes a reference payload
/// when it is bound into an interface wrapper.
///
/// `Some(true)` names an allocation a wrapper keeps by reference: a pointed-to
/// object or a channel. `Some(false)` proves an inline value or a slice or map
/// header, whose descriptor the wrapper copies. `None` means the shape is
/// unavailable, so the wrapper stays unnamed. The caller must hold a semantic
/// Allocation row at this offset, exactly as for the binding-mode question.
pub fn allocation_boxes_reference_payload_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "allocation_boxes_reference_payload_at_offset",
    )
    .and_then(|support| support.allocation_boxes_reference_payload_at_offset(file, source, offset))
}

/// Whether one exact indexed Go callable result binds by reference.
///
/// The analyzer declaration range identifies the callable; the Go adapter then
/// maps the requested result ordinal through the declaration's AST. Unsupported
/// nominal, generic, alias, and recovery cases remain unknown.
pub fn result_binds_by_reference_at_ordinal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    declaration: &CodeUnit,
    ordinal: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "result_binds_by_reference_at_ordinal",
    )
    .and_then(|support| {
        support.result_binds_by_reference_at_ordinal(analyzer, file, source, declaration, ordinal)
    })
}

/// Exact pointer-versus-copy binding for a parameter at a callable source
/// span, including anonymous Go literals. Backing descriptors remain copies
/// in this domain; unavailable type or source identity remains unknown.
pub fn parameter_binds_by_reference_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "parameter_binds_by_reference_at_span",
    )
    .and_then(|support| {
        support.parameter_binds_by_reference_at_span(file, source, start, end, ordinal)
    })
}

/// Whether one exact Go callable parameter copies a slice, map, or channel
/// descriptor while preserving its backing storage. Unsupported named types
/// and missing source identity remain unknown.
pub fn parameter_preserves_backing_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "parameter_preserves_backing_at_span",
    )
    .and_then(|support| {
        support.parameter_preserves_backing_at_span(file, source, start, end, ordinal)
    })
}

/// Whether one exact Go callable parameter's declared type is an interface
/// that boxes one reference payload. A copied interface argument still carries
/// the caller's object inside the wrapper. Unavailable or ambiguous type
/// declarations remain unknown.
pub fn parameter_boxes_reference_payload_at_span(
    file: &ProjectFile,
    source: &str,
    start: usize,
    end: usize,
    ordinal: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "parameter_boxes_reference_payload_at_span",
    )
    .and_then(|support| {
        support.parameter_boxes_reference_payload_at_span(file, source, start, end, ordinal)
    })
}

/// Whether one exact indexed Go callable parameter is proven to be a
/// reference-free primitive value. Unsupported or shadowed types remain
/// unknown.
pub fn parameter_is_reference_free_at_ordinal(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    declaration: &CodeUnit,
    ordinal: usize,
) -> Option<bool> {
    language_support_for_hook(
        language_for_file(file),
        "parameter_is_reference_free_at_ordinal",
    )
    .and_then(|support| {
        support.parameter_is_reference_free_at_ordinal(analyzer, file, source, declaration, ordinal)
    })
}

/// Prove that an exact selector occurrence names a modeled method declaration.
/// This consumes resolver-owned selection evidence, not the receiver shape of
/// a callable value that might have been loaded from a mutable field.
pub fn modeled_method_selection_at_offset(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<String> {
    language_support_for_hook(
        language_for_file(file),
        "modeled_method_selection_at_offset",
    )
    .and_then(|support| support.modeled_method_selection_at_offset(analyzer, file, source, offset))
}

/// Whether the Go lexical binding declared at `offset` may be created more
/// than once during one procedure invocation.
///
/// `None` means the offset is not an exact supported binding identifier, the
/// source could not be parsed, or recovery made the relevant AST path
/// unreliable. Languages without this distinction remain unsupported rather
/// than being classified as singleton storage.
pub fn lexical_binding_repeats_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<bool> {
    language_support_for_hook(language_for_file(file), "lexical_binding_repeats_at_offset")
        .and_then(|support| support.lexical_binding_repeats_at_offset(file, source, offset))
}

/// The declaration one offset falls inside, for a consumer holding an
/// analyzer.
///
/// [`navigation_declaration_site_at_offset`] answers from source alone. Go's
/// declarations come from the analyzer, so this takes one. A caller asking
/// what declaration an occurrence *is*, rather than what it refers to, needs
/// this: a definition lookup at a declaration has no reference to follow.
pub fn declaration_site_at_offset(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<CodeUnit> {
    language_support_for_hook(language_for_file(file), "declaration_site_at_offset")
        .and_then(|support| support.declaration_site_at_offset(analyzer, file, source, offset))
}

pub fn navigation_declaration_site_at_offset(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<CodeUnit> {
    language_support_for_hook(
        language_for_file(file),
        "navigation_declaration_site_at_offset",
    )
    .and_then(|support| {
        support.navigation_declaration_site_at_offset(analyzer, file, source, offset)
    })
}

pub fn resolve_definition_batch_with_source_and_cancellation(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: &CancellationToken,
) -> Vec<DefinitionLookupOutcome> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = definition_batch_context_with_source(analyzer, scope.token(), file, source);
    resolve_definition_requests(
        analyzer,
        token,
        &mut context,
        requests,
        Some(cancellation),
        None,
    )
}

// One file window retains owned preparation; request guards remain per lookup.
pub(crate) struct ScalarCallTargetSession<'a> {
    analyzer: &'a dyn IAnalyzer,
    resolver: Option<Box<dyn DefinitionBatchResolver<'a> + 'a>>,
    initialized: bool,
    disabled: bool,
    memo: Option<ScalarDefinitionMemo>,
}

struct ScalarDefinitionMemo {
    language_state: HashMap<std::any::TypeId, Box<dyn std::any::Any>>,
    sources: HashMap<ProjectFile, Result<Arc<str>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    primary_source_tree: Option<(ProjectFile, Tree)>,
    line_starts: HashMap<ProjectFile, Arc<Vec<usize>>>,
    enclosing_owner_chains: HashMap<CodeUnit, Arc<Vec<CodeUnit>>>,
}

impl<'a> ScalarCallTargetSession<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            resolver: None,
            initialized: false,
            disabled: false,
            memo: None,
        }
    }

    pub(crate) fn release_before_store_read(&mut self) {
        if let Some(resolver) = &mut self.resolver {
            resolver.release_before_store_read();
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.resolver.is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve(
        &mut self,
        token: QueryToken<'_>,
        requests: Vec<DefinitionLookupRequest>,
        file: ProjectFile,
        source: Arc<str>,
        primary_tree: &Tree,
        cancellation: Option<&CancellationToken>,
    ) -> Vec<CallTargetLookupOutcome> {
        let _timing = profiling::scope("get_definition::resolve_call_target_batch");
        assert_eq!(
            requests.len(),
            1,
            "file-window dispatch retains scalar demand"
        );
        let analyzer = self.analyzer;
        if !self.initialized {
            self.resolver =
                language_support_for_hook(language_for_file(&file), "definition_batch_resolver")
                    .and_then(|support| support.definition_batch_resolver(analyzer, cancellation));
            self.initialized = true;
            if let Some(resolver) = &mut self.resolver {
                resolver.retain_file_operation();
            } else {
                self.disabled = true;
            }
        }
        if self.disabled {
            return resolve_call_target_batch_with_source_tree(
                analyzer,
                token,
                requests,
                file,
                source,
                Some(primary_tree.clone()),
                cancellation,
            );
        }
        // Request guards are recreated on demand; only the context's owned
        // memo state survives. The bounded reader's incomplete-read flag is
        // request-local too. A QueryToken must never borrow an owned guard
        // in the same struct, nor be extended beyond its actual scope.
        let scope = AnalyzerQueryScope::new(analyzer);
        let mut context = DefinitionBatchContext::new(analyzer, scope.token());
        if let Some(memo) = self.memo.take() {
            context.language_state = memo.language_state;
            context.sources = memo.sources;
            context.trees = memo.trees;
            context.primary_source_tree = memo.primary_source_tree;
            context.line_starts = memo.line_starts;
            context.enclosing_owner_chains = memo.enclosing_owner_chains;
        } else {
            context.sources.insert(file.clone(), Ok(source));
            context.primary_source_tree = Some((file.clone(), primary_tree.clone()));
        }
        let _deadline = cancellation
            .map(|cancellation| AnalyzerQueryScope::with_cancellation(analyzer, cancellation));
        record_definition_batch_probe_reads(analyzer, &mut context, &requests);
        let outcomes = resolve_call_target_requests(
            analyzer,
            token,
            &mut context,
            requests,
            cancellation,
            self.resolver
                .as_mut()
                .map(|batch| batch.as_mut() as &mut dyn DefinitionBatchResolver<'a>),
        );
        // Release any reader that excludes other store access at the lookup
        // boundary, before the caller expands targets or starts another lookup.
        self.release_before_store_read();
        if cancellation.is_some_and(CancellationToken::is_cancelled)
            || scope.store_error().is_some()
            || context.read_scope.store_error().is_some()
            || outcomes.iter().any(|outcome| {
                outcome.outcome.diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.kind.as_str(),
                        "native_stale" | "native_store_error"
                    )
                })
            })
        {
            self.disabled = true;
            self.resolver = None;
            self.memo = None;
            return outcomes;
        }
        self.memo = Some(ScalarDefinitionMemo {
            language_state: context.language_state,
            sources: context.sources,
            trees: context.trees,
            primary_source_tree: context.primary_source_tree,
            line_starts: context.line_starts,
            enclosing_owner_chains: context.enclosing_owner_chains,
        });
        outcomes
    }
}

impl Drop for ScalarCallTargetSession<'_> {
    fn drop(&mut self) {
        self.resolver = None;
        self.memo = None;
    }
}

pub fn resolve_call_target_batch_with_source(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: Option<&CancellationToken>,
) -> Vec<CallTargetLookupOutcome> {
    resolve_call_target_batch_with_source_tree(
        analyzer,
        token,
        requests,
        file,
        source,
        None,
        cancellation,
    )
}

/// Resolve against an exact source and its primary parser tree. Language hooks
/// retain ownership of any transformed definition tree, such as Python's
/// stitched tree; an embedded call tree is not a primary source tree.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_call_target_batch_with_source_tree(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    primary_tree: Option<Tree>,
    cancellation: Option<&CancellationToken>,
) -> Vec<CallTargetLookupOutcome> {
    let _scope = profiling::scope("get_definition::resolve_call_target_batch");
    if profiling::enabled() {
        profiling::note(format!("request_count={}", requests.len()));
    }
    match language_support_for_hook(
        language_for_file(&file),
        "resolve_definition_call_target_batch",
    ) {
        Some(support) => support.resolve_definition_call_target_batch(
            analyzer,
            token,
            requests,
            file,
            source,
            primary_tree,
            cancellation,
        ),
        None => resolve_generic_call_target_batch(
            analyzer,
            token,
            requests,
            file,
            source,
            primary_tree,
            cancellation,
        ),
    }
}

pub(crate) fn resolve_generic_call_target_batch(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    primary_tree: Option<Tree>,
    cancellation: Option<&CancellationToken>,
) -> Vec<CallTargetLookupOutcome> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    context.sources.insert(file.clone(), Ok(source));
    context.primary_source_tree = primary_tree.map(|tree| (file.clone(), tree));
    debug_assert!(
        requests.iter().all(|request| request.file == file),
        "one call-target source batch must contain requests for that source file"
    );

    // C/C++ call targets are navigation answers: one call names a declaration
    // whose defining body the link-unit selection has to choose, so the
    // request runs the navigation route and reports what that selection could
    // not prove.
    if language_for_file(&file) == Language::Cpp {
        return resolve_navigation_requests(
            analyzer,
            token,
            &mut context,
            requests,
            NavigationOperation::Definition,
            cancellation,
        )
        .into_iter()
        .map(|navigation| CallTargetLookupOutcome {
            authority: navigation.evidence.authority,
            call_application: navigation.evidence.call_application,
            dispatch_extensibility: navigation.evidence.dispatch_extensibility,
            exact_external_call: navigation.evidence.exact_external_call,
            external_callee_identity: navigation.evidence.external_callee_identity,
            structure_unavailable: navigation.structure_unavailable,
            unproven_link_unit: navigation.unproven_link_unit,
            truncated: navigation.truncated,
            outcome: DefinitionLookupOutcome {
                modeled_definitions: navigation.modeled_definitions,
                status: navigation.status,
                reference: navigation.reference,
                definitions: navigation
                    .targets
                    .into_iter()
                    .map(|target| target.code_unit)
                    .collect(),
                lexical_definition: navigation.lexical_definition,
                diagnostics: navigation.diagnostics,
            },
        })
        .collect();
    }

    // Every other language takes one route, and it keeps whatever its resolver
    // proved. Nothing here enumerates the languages that publish evidence:
    // that list existed, and it silently flattened Ruby's boundary proof to
    // `None` for as long as Ruby was absent from it (#3459, #3496).
    //
    // A call-target batch names what it probes once, up front, and lets each
    // resolver's own reads land on the ambient ledger, rather than running the
    // definition route's per-request capture. The difference is visible:
    // `publish_definition_reads` trades a resolved request's speculative index
    // probes for its declarations' fact digests, and for an edited callee that
    // turns the caller's unit from an exact file dependency into a
    // whole-language scope dependency (`read_ledger_verification::
    // an_edited_callee_invalidates_the_callees_unit`). The caller's deadline
    // still reaches the reads below, which is what the discarded route
    // contributed.
    let _deadline = cancellation
        .map(|cancellation| AnalyzerQueryScope::with_cancellation(analyzer, cancellation));
    record_definition_batch_probe_reads(analyzer, &mut context, &requests);
    let mut definition_batch = (!requests.is_empty())
        .then(|| {
            language_support_for_hook(language_for_file(&file), "definition_batch_resolver")
                .and_then(|support| support.definition_batch_resolver(analyzer, cancellation))
        })
        .flatten();
    resolve_call_target_requests(
        analyzer,
        token,
        &mut context,
        requests,
        cancellation,
        definition_batch
            .as_mut()
            .map(|batch| batch.as_mut() as &mut dyn DefinitionBatchResolver<'_>),
    )
}

#[doc(hidden)]
pub fn resolve_call_target_requests<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
    mut definition_batch: Option<&mut dyn DefinitionBatchResolver<'a>>,
) -> Vec<CallTargetLookupOutcome> {
    if let Some(batch) = definition_batch.as_mut() {
        batch.precompute(analyzer, context, &requests, cancellation);
    }
    requests
        .into_iter()
        .map(|request| {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return CallTargetLookupOutcome::from_resolution(
                    cancelled("call-target resolution was cancelled").into(),
                );
            }
            CallTargetLookupOutcome::from_resolution(resolve_one_with_evidence(
                analyzer,
                token,
                context,
                request,
                None,
                cancellation,
                None,
                definition_batch
                    .as_mut()
                    .map(|batch| &mut **batch as &mut dyn DefinitionBatchResolver<'a>),
            ))
        })
        .collect()
}

pub fn resolve_call_reference_definition_with_source(
    analyzer: &dyn IAnalyzer,
    request: DefinitionLookupRequest,
    file: ProjectFile,
    source: Arc<str>,
) -> Option<DefinitionLookupOutcome> {
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let language = language_for_file(&request.file);
    if matches!(language, Language::None | Language::Ruby) {
        return None;
    }
    let start_byte = request.start_byte?;
    let end_byte = request.end_byte?;
    if start_byte >= end_byte {
        return None;
    }

    let scope = AnalyzerQueryScope::new(analyzer);
    let mut context = DefinitionBatchContext::new(analyzer, scope.token());
    context.sources.insert(file, Ok(source));
    let source = context.source(&request.file).ok()?;
    let tree = context.tree(&request.file, language, &source)?;
    if !is_call_reference_range_in_tree(&tree, language, start_byte, end_byte) {
        return None;
    }

    record_definition_batch_probe_reads(analyzer, &mut context, std::slice::from_ref(&request));
    Some(resolve_one(
        analyzer,
        token,
        &mut context,
        request,
        None,
        None,
    ))
}

#[doc(hidden)]
pub struct DefinitionBatchContext<'a: 'token, 'token> {
    #[doc(hidden)]
    pub route: DefinitionBatchRoute,
    #[doc(hidden)]
    pub analyzer: &'a dyn IAnalyzer,
    /// Proof that the batch's request scope is open for the batch's whole life
    /// (issue #2414 step 3).
    #[doc(hidden)]
    pub token: QueryToken<'token>,
    #[doc(hidden)]
    pub bounded_support: AnalyzerDefinitionLookup<'a>,
    #[doc(hidden)]
    pub language_state: HashMap<std::any::TypeId, Box<dyn std::any::Any>>,
    #[doc(hidden)]
    pub sources: HashMap<ProjectFile, Result<Arc<str>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    primary_source_tree: Option<(ProjectFile, Tree)>,
    #[doc(hidden)]
    pub line_starts: HashMap<ProjectFile, Arc<Vec<usize>>>,
    // Covers visibility construction as well as candidate lookup. Incomplete
    // reads stay visible after a nested cancelling scope closes.
    #[doc(hidden)]
    pub read_scope: AnalyzerQueryScope<'a>,
    #[doc(hidden)]
    pub enclosing_owner_chains: HashMap<CodeUnit, Arc<Vec<CodeUnit>>>,
    #[doc(hidden)]
    pub navigation_operation: Option<NavigationOperation>,
    #[doc(hidden)]
    pub exact_token_focus: bool,
}

impl<'a: 'token, 'token> DefinitionBatchContext<'a, 'token> {
    #[doc(hidden)]
    pub fn new(analyzer: &'a dyn IAnalyzer, token: QueryToken<'token>) -> Self {
        Self {
            analyzer,
            token,
            route: DefinitionBatchRoute::default(),
            bounded_support: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            language_state: HashMap::default(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            primary_source_tree: None,
            line_starts: HashMap::default(),
            read_scope: AnalyzerQueryScope::new(analyzer),
            enclosing_owner_chains: HashMap::default(),
            navigation_operation: None,
            exact_token_focus: false,
        }
    }

    #[doc(hidden)]
    pub fn language_state<T: Default + 'static>(&mut self) -> &mut T {
        self.language_state
            .entry(std::any::TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()))
            .downcast_mut::<T>()
            .expect("definition language state matches its type key")
    }

    #[doc(hidden)]
    pub fn language_state_ref<T: Default + 'static>(&self) -> &T {
        self.language_state
            .get(&std::any::TypeId::of::<T>())
            .expect("definition language state was initialized")
            .downcast_ref::<T>()
            .expect("definition language state matches its type key")
    }

    #[doc(hidden)]
    pub fn bounded_support(&self) -> &dyn BoundedDefinitionLookup {
        &self.bounded_support
    }

    #[doc(hidden)]
    pub fn source(&mut self, file: &ProjectFile) -> Result<Arc<str>, String> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| read_source(file).map(Arc::<str>::from))
            .clone()
    }

    #[doc(hidden)]
    pub fn tree(&mut self, file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
        self.trees
            .entry((file.clone(), language))
            .or_insert_with(|| {
                language_support_for_hook(language, "definition_tree").and_then(|support| {
                    support.definition_tree(
                        self.analyzer,
                        self.token,
                        file,
                        language,
                        source,
                        self.primary_source_tree
                            .as_ref()
                            .and_then(|(tree_file, tree)| {
                                (tree_file == file && language == language_for_file(file))
                                    .then_some(tree)
                            }),
                    )
                })
            })
            .clone()
    }

    #[doc(hidden)]
    pub fn line_starts(&mut self, file: &ProjectFile, source: &str) -> Arc<Vec<usize>> {
        self.line_starts
            .entry(file.clone())
            .or_insert_with(|| Arc::new(compute_line_starts(source)))
            .clone()
    }

    /// Generalized, memoized version of the enclosing-owner-chain walk (see
    /// `common::enclosing_owner_chain`): `owner` plus every contiguous
    /// ancestor `accept` approves, stopping at the first rejection.
    ///
    /// The cache key is `owner` alone, not `(owner, accept)` — every caller
    /// today shares one predicate (C++'s `CodeUnit::is_class`). A second
    /// predicate reused through this same cache would silently return the
    /// first-cached chain for a given owner; give it a predicate-aware key
    /// before adding one.
    #[doc(hidden)]
    pub fn enclosing_owner_chain(
        &mut self,
        owner: CodeUnit,
        accept: impl Fn(&CodeUnit) -> bool,
    ) -> Arc<Vec<CodeUnit>> {
        let analyzer = self.analyzer;
        self.enclosing_owner_chains
            .entry(owner.clone())
            .or_insert_with(|| {
                Arc::new(
                    crate::analyzer::usages::common::enclosing_owner_chain(owner, |unit| {
                        analyzer.parent_of(unit)
                    })
                    .take_while(|unit| accept(unit))
                    .collect(),
                )
            })
            .clone()
    }
}

/// The reference site one request names, focused the way the language's own
/// resolver focuses it.
///
/// Stated once because two readers must agree on it by construction: the
/// resolver, which resolves the focused token, and the batch entry, which
/// records the index keys that token probes before any resolver can return
/// without probing. A second spelling of this in either place would record a
/// name the resolver never asked for and, worse, miss the one it did.
#[doc(hidden)]
pub fn focused_reference_site(
    context: &mut DefinitionBatchContext<'_, '_>,
    request: &DefinitionLookupRequest,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
) -> Result<ResolvedReferenceSite, String> {
    let _scope = profiling::scope("get_definition::reference_site");
    let line_starts = context.line_starts(&request.file, source);
    let site = resolve_reference_site_with_line_starts(
        &request.as_source_location(),
        source,
        &line_starts,
        tree.map(Tree::root_node),
    )?;
    Ok(match tree {
        Some(tree) => match language_support_for_hook(language, "definition_site_for_focus") {
            Some(support) => support.definition_site_for_focus(
                site,
                tree,
                source,
                request.start_byte,
                request.end_byte,
            ),
            None => site,
        },
        None => site,
    })
}

fn resolve_one<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    request: DefinitionLookupRequest,
    operation: Option<NavigationOperation>,
    cancellation: Option<&CancellationToken>,
) -> DefinitionLookupOutcome {
    resolve_one_with_evidence(
        analyzer,
        token,
        context,
        request,
        operation,
        cancellation,
        None,
        None,
    )
    .outcome
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn resolve_one_with_evidence<'a>(
    analyzer: &'a dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'a, '_>,
    request: DefinitionLookupRequest,
    operation: Option<NavigationOperation>,
    cancellation: Option<&CancellationToken>,
    go_session: Option<&ResolutionSession>,
    definition_batch: Option<&mut dyn DefinitionBatchResolver<'a>>,
) -> DefinitionResolution {
    let _scope = profiling::scope("get_definition::resolve_one");
    context.navigation_operation = operation;
    let language = language_for_file(&request.file);
    context.bounded_support.set_language(language);
    if profiling::enabled() {
        profiling::note(format!("language={language:?}"));
    }
    if matches!(language, Language::None) {
        return diagnostic_outcome(
            DefinitionLookupStatus::UnsupportedLanguage,
            "unsupported_language",
            format!("{language:?} get_definition is not implemented yet"),
        )
        .into();
    }

    let source = {
        let _scope = profiling::scope("get_definition::source");
        match context.source(&request.file) {
            Ok(source) => source,
            Err(message) => {
                return diagnostic_outcome(
                    DefinitionLookupStatus::NotFound,
                    "file_read_failed",
                    message,
                )
                .into();
            }
        }
    };

    let tree = {
        let _scope = profiling::scope("get_definition::parse_tree");
        context.tree(&request.file, language, &source)
    };

    let site = match focused_reference_site(context, &request, language, &source, tree.as_ref()) {
        Ok(site) => site,
        Err(message) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::InvalidLocation,
                "invalid_location",
                message,
            )
            .into();
        }
    };
    let site = match language_support_for_hook(language, "definition_lexical_site")
        .expect("supported definition language")
        .definition_lexical_site(analyzer, context, &request, &source, tree.as_ref(), site)
    {
        std::ops::ControlFlow::Break(resolution) => return resolution,
        std::ops::ControlFlow::Continue(site) => site,
    };
    // Rust lexical declarations are projected by the native operation with
    // the same source authority and completion as item definitions.
    if language != Language::Rust
        && let Some(tree) = tree.as_ref()
        && let Some(identifier) = source.get(site.focus_start_byte..site.focus_end_byte)
    {
        let lexical_binding = resolve_lexical_binding(
            language,
            tree.root_node(),
            &source,
            site.focus_start_byte,
            site.focus_end_byte,
            identifier,
        )
        .or_else(|| {
            language_support_for_hook(language, "definition_lexical_fallback").and_then(|support| {
                support.definition_lexical_fallback(
                    analyzer,
                    token,
                    &request.file,
                    &source,
                    tree,
                    &site,
                    identifier,
                )
            })
        });
        match lexical_binding {
            Some(
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition),
            ) => {
                return finish_lookup_outcome(lexical_definition_outcome(definition), site).into();
            }
            None => {}
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    if let Some(resolution) =
        language_support_for_hook(language, "trial_definition").and_then(|support| {
            let query = crate::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file: &request.file,
                source: &source,
                tree: tree.as_ref(),
                site: &site,
                budget: crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
                cancellation,
            };
            support.trial_definition(query)
        })
    {
        return resolution;
    }
    let native_points = language_support_for_hook(language, "default_definition_points")
        .and_then(|support| support.default_definition_points());
    #[cfg(any(test, feature = "test-support"))]
    let native_points = native_points.or_else(|| {
        (language == Language::Scala && std::env::var_os("BIFROST_TRIAL_NATIVE_SCALA").is_some())
            .then(|| {
                language_support_for_hook(language, "native_rollout_points")
                    .and_then(|support| support.native_rollout_points())
            })
            .flatten()
    });
    if let Some(native_points) = native_points {
        let query = crate::analyzer::languages::BoundedReceiverQuery {
            analyzer,
            file: &request.file,
            source: &source,
            tree: tree.as_ref(),
            site: &site,
            budget: crate::analyzer::usages::receiver_analysis::INTERACTIVE_TYPE_LOOKUP_BUDGET,
            cancellation,
        };
        return match crate::analyzer::languages::StructuralReceiverResolver::
            resolve_definition_bounded(
                native_points,
                query,
            )
        {
            BoundedResolution::Complete { value, .. } => DefinitionResolution {
                outcome: value,
                evidence: CallEvidence::default(),
            },
            BoundedResolution::Exceeded { limit, .. } => exceeded_budget(
                limit,
                format!(
                    "{language:?} definition resolution exceeded its {} budget",
                    limit.as_str()
                ),
            )
            .into(),
            BoundedResolution::Cancelled { .. } => {
                cancelled(format!("{language:?} definition resolution was cancelled")).into()
            }
        };
    }
    let _dispatch_scope = profiling::scope("get_definition::language_dispatch");
    let support = language_support_for_hook(language, "resolve_definition_dispatch")
        .expect("supported definition language");
    let resolution = match definition_batch {
        Some(batch) => batch.resolve_definition_dispatch(
            analyzer,
            token,
            context,
            &request,
            &source,
            &tree,
            &site,
            operation,
            cancellation,
            go_session,
        ),
        None => support.resolve_definition_dispatch(
            analyzer,
            token,
            context,
            &request,
            &source,
            &tree,
            &site,
            operation,
            cancellation,
            go_session,
        ),
    };
    let DefinitionResolution {
        outcome: resolved,
        evidence,
    } = match resolution {
        std::ops::ControlFlow::Break(resolution) => return resolution,
        std::ops::ControlFlow::Continue(resolution) => resolution,
    };

    let resolved = if let Some(operation) = operation {
        if language == Language::Cpp {
            resolved
        } else {
            finalize_navigation_outcome(resolved, operation)
        }
    } else {
        resolved
    };

    DefinitionResolution {
        outcome: finish_lookup_outcome(resolved, site),
        evidence,
    }
}

#[doc(hidden)]
pub fn finish_lookup_outcome(
    mut outcome: DefinitionLookupOutcome,
    site: ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    if outcome.reference.is_none() {
        outcome.reference = Some(site);
    }
    outcome
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum QualifiedAccessFocus {
    Qualifier,
    Member,
}

#[doc(hidden)]
pub fn qualified_access_focus(
    focus: Node<'_>,
    access: Node<'_>,
    qualifier_fields: &[&str],
    member_fields: &[&str],
) -> Option<QualifiedAccessFocus> {
    if fields_contain_focus(access, qualifier_fields, focus) {
        return Some(QualifiedAccessFocus::Qualifier);
    }
    if fields_contain_focus(access, member_fields, focus) {
        return Some(QualifiedAccessFocus::Member);
    }
    None
}

fn fields_contain_focus(access: Node<'_>, fields: &[&str], focus: Node<'_>) -> bool {
    fields.iter().any(|field| {
        access
            .child_by_field_name(field)
            .is_some_and(|child| node_contains_focus(child, focus))
    })
}

#[doc(hidden)]
pub fn node_contains_focus(node: Node<'_>, focus: Node<'_>) -> bool {
    node.id() == focus.id()
        || (node.start_byte() <= focus.start_byte() && focus.end_byte() <= node.end_byte())
}

/// A whole-file parse memoized on the exact source bytes, the issue #1219
/// `parse_rust_tree` pattern generalized for the other language resolvers
/// (#2679).
///
/// The definition resolvers re-parse files the batch caches cannot reach:
/// Java re-parses the file it is resolving in once per local-type candidate,
/// Kotlin re-parses every declaring file it inspects once per occurrence, and
/// Go re-parses package variable files per selector chain. A parse is a pure
/// function of the source bytes, so the memo is observationally identical,
/// and the byte-weighted cache ages stale sources out exactly like the Rust
/// tree memo in `bifrost-rust`.
///
/// One memo per language: source bytes alone must never answer for a
/// different grammar's parse.
#[doc(hidden)]
pub struct TreeParseMemo {
    cache: OnceLock<Cache<Arc<str>, Option<Tree>>>,
}

const TREE_PARSE_MEMO_SOURCE_BUDGET_BYTES: u64 = 32 * 1024 * 1024;

impl TreeParseMemo {
    #[doc(hidden)]
    pub const fn new() -> Self {
        Self {
            cache: OnceLock::new(),
        }
    }

    fn cache(&self) -> &Cache<Arc<str>, Option<Tree>> {
        self.cache.get_or_init(|| {
            build_weighted_cache(TREE_PARSE_MEMO_SOURCE_BUDGET_BYTES, weight_source_text)
        })
    }

    #[doc(hidden)]
    pub fn parse(&self, source: &str, parse: impl FnOnce(&str) -> Option<Tree>) -> Option<Tree> {
        let cache = self.cache();
        if let Some(tree) = cache.get(source) {
            return tree;
        }
        let tree = parse(source);
        cache.insert(Arc::from(source), tree.clone());
        tree
    }
}

/// Parse `source` under the grammar registered for `language`.
///
/// `file` selects the grammar flavor, which TypeScript distinguishes for `.tsx`.
/// C# additionally uses its directive-aware pre-parse so every consumer sees the
/// same selected conditional-compilation branches as declaration extraction and
/// usage analysis. `None` means the language has no grammar (`Language::None`) or
/// the source did not parse.
pub fn parse_tree_for_language(
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    if language == Language::CSharp {
        return brokk_bifrost_csharp::preprocessor::parse_csharp(source);
    }
    if language == Language::Go {
        return brokk_bifrost_go::parse::parse_go(source);
    }
    let grammar = crate::analyzer::parser_language_for_path(language, file.rel_path())?;
    let mut parser = Parser::new();
    parser.set_language(&grammar).ok()?;
    let tree = parser.parse(source, None)?;
    if language == Language::Cpp
        && let Some(ranges) =
            brokk_bifrost_cpp::graph::syntax::function_macro_included_ranges(source, &tree, || {
                false
            })
            .continue_value()?
    {
        drop(tree);
        parser.set_included_ranges(&ranges).ok()?;
        return parser.parse(source, None);
    }
    Some(tree)
}

#[doc(hidden)]
pub fn candidates_outcome(mut candidates: Vec<CodeUnit>) -> DefinitionLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    let mut semantic_keys = HashSet::default();
    for candidate in &candidates {
        semantic_keys.insert(definition_symbol_key(candidate));
    }
    // Zero candidates is "nothing was found", never an ambiguity: an answer
    // that lists nothing gives a caller nothing to choose between (#1811).
    let (status, diagnostics) = match semantic_keys.len() {
        0 => (
            DefinitionLookupStatus::NoDefinition,
            vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: "no_indexed_definition".to_string(),
                message: "the reference resolved to no workspace definition".to_string(),
            }],
        ),
        1 => (DefinitionLookupStatus::Resolved, Vec::new()),
        _ => (
            DefinitionLookupStatus::Ambiguous,
            vec![DefinitionLookupDiagnostic {
                claim: None,
                kind: "ambiguous_definition".to_string(),
                message: "reference resolved to multiple workspace definitions".to_string(),
            }],
        ),
    };
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: None,
        definitions: candidates,
        lexical_definition: None,
        diagnostics,
    };
    trace::record_selected_units(&outcome);
    outcome
}

#[doc(hidden)]
pub fn finalize_navigation_outcome(
    mut outcome: DefinitionLookupOutcome,
    operation: NavigationOperation,
) -> DefinitionLookupOutcome {
    sort_units(&mut outcome.definitions);
    outcome.definitions.dedup();
    if matches!(
        outcome.status,
        DefinitionLookupStatus::Unavailable
            | DefinitionLookupStatus::Cancelled
            | DefinitionLookupStatus::ExceededBudget(_)
    ) {
        // A stopped resolver or unavailable source authority cannot publish
        // a target prefix. Retain its status and diagnostics only.
        outcome.definitions.clear();
        outcome.modeled_definitions.clear();
        outcome.lexical_definition = None;
        return outcome;
    }
    if matches!(
        outcome.status,
        DefinitionLookupStatus::Incomplete | DefinitionLookupStatus::Ambiguous
    ) {
        // Presentation cardinality cannot strengthen canonical binding proof.
        // Distinct canonical alternatives can project to the same display target.
        return outcome;
    }
    if outcome.lexical_definition.is_some() {
        outcome.status = DefinitionLookupStatus::Resolved;
        return outcome;
    }
    if outcome.definitions.is_empty() {
        return outcome;
    }
    outcome.status = if outcome.definitions.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    outcome
        .diagnostics
        .retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
    if outcome.status == DefinitionLookupStatus::Ambiguous {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_string(),
            message: format!(
                "{} navigation resolved to multiple workspace targets",
                match operation {
                    NavigationOperation::Declaration => "declaration",
                    NavigationOperation::Definition => "definition",
                }
            ),
        });
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
#[doc(hidden)]
pub fn navigation_lookup_outcome(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    context: &mut DefinitionBatchContext<'_, '_>,
    reference_file: &ProjectFile,
    resolution: DefinitionResolution,
    language: Language,
    operation: NavigationOperation,
) -> NavigationLookupOutcome {
    let DefinitionResolution { outcome, evidence } = resolution;
    let DefinitionLookupOutcome {
        mut modeled_definitions,
        mut status,
        reference,
        mut definitions,
        mut lexical_definition,
        mut diagnostics,
    } = outcome;
    if matches!(
        status,
        DefinitionLookupStatus::Unavailable
            | DefinitionLookupStatus::Cancelled
            | DefinitionLookupStatus::ExceededBudget(_)
    ) {
        // Unavailable authority and stopped work publish no target prefix.
        definitions.clear();
        modeled_definitions.clear();
        lexical_definition = None;
    }
    let (mut targets, structure_unavailable, unproven_link_unit, mut truncated) =
        if language == Language::Cpp {
            // C++ candidates_outcome already groups one logical symbol across
            // physical declarations as Resolved, and bypasses the generic
            // definition finalizer. Its occurrence selector can therefore choose
            // that symbol's body or conditional-family representative below.
            // Explicit Ambiguous outcomes also cover base-subobject and receiver
            // uncertainty; selecting one occurrence cannot discharge those proofs.
            let selection = language_support_for_hook(language, "definition_navigation_selection")
                .expect("supported navigation language")
                .definition_navigation_selection(
                    context,
                    token,
                    reference_file,
                    &definitions,
                    operation,
                )
                .expect("C++ navigation selects physical occurrences");
            (
                selection.targets,
                selection.structure_unavailable
                    || diagnostics.iter().any(|diagnostic| {
                        diagnostic.kind == CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC
                    }),
                selection.unproven_link_unit,
                selection.truncated,
            )
        } else {
            // A reference's definition is the resolver's answer. The resolver
            // already names an impl's associated type for a concrete qualifier
            // (`View::Node`), so a trait's declaration here means the qualifier is
            // bounded by traits: a type parameter (`G::Node` under `G: Dense`) or
            // `Self` in a trait body. Every impl of the trait is not a definition
            // of that reference, so only the upward (declaration) direction
            // follows the member family. A click on the trait's own declaration
            // still reaches its impls (`navigation_declaration_site_targets`).
            let mut targets: Vec<_> = definitions
                .iter()
                .cloned()
                .flat_map(|code_unit| match operation {
                    NavigationOperation::Declaration => {
                        match language_support_for_hook(
                            language_for_file(code_unit.source()),
                            "definition_associated_navigation_targets",
                        ) {
                            Some(support) => support.definition_associated_navigation_targets(
                                analyzer, token, code_unit, operation,
                            ),
                            None => vec![NavigationTarget {
                                code_unit,
                                declaration_range: None,
                            }],
                        }
                    }
                    NavigationOperation::Definition => vec![NavigationTarget {
                        code_unit,
                        declaration_range: None,
                    }],
                })
                .collect();
            let truncated = targets.len() > MAX_NAVIGATION_TARGETS_PER_RESULT;
            targets.truncate(MAX_NAVIGATION_TARGETS_PER_RESULT);
            (targets, false, false, truncated)
        };
    targets.sort_by(|left, right| {
        (&left.code_unit, left.declaration_range).cmp(&(&right.code_unit, right.declaration_range))
    });
    targets.dedup();
    let remaining = MAX_NAVIGATION_TARGETS_PER_RESULT.saturating_sub(targets.len());
    if modeled_definitions.len() > remaining {
        modeled_definitions.truncate(remaining);
        truncated = true;
        if status == DefinitionLookupStatus::Resolved {
            status = DefinitionLookupStatus::Ambiguous;
        }
    }

    diagnostics.retain(|diagnostic| {
        !matches!(
            diagnostic.kind.as_str(),
            "no_definition"
                | "no_declaration"
                | NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC
                | CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC
        )
    });

    if matches!(
        status,
        DefinitionLookupStatus::Incomplete
            | DefinitionLookupStatus::Ambiguous
            | DefinitionLookupStatus::Unavailable
            | DefinitionLookupStatus::Cancelled
            | DefinitionLookupStatus::ExceededBudget(_)
    ) {
        // Preserve canonical uncertainty and operational authority even when
        // presentation deduplication leaves a single target.
    } else if lexical_definition.is_some() {
        status = DefinitionLookupStatus::Resolved;
        truncated = false;
    } else if targets.is_empty() {
        if !definitions.is_empty() {
            diagnostics.retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
            status = DefinitionLookupStatus::NoDefinition;
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: match operation {
                    NavigationOperation::Declaration => "no_declaration",
                    NavigationOperation::Definition => "no_definition",
                }
                .to_string(),
                message: match operation {
                    NavigationOperation::Declaration => {
                        "navigation candidates contain no declaration target"
                    }
                    NavigationOperation::Definition => {
                        "navigation candidates contain no implementation body"
                    }
                }
                .to_string(),
            });
        }
    } else {
        diagnostics.retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
        status = if targets.len() == 1 && !truncated {
            DefinitionLookupStatus::Resolved
        } else {
            DefinitionLookupStatus::Ambiguous
        };
        if status == DefinitionLookupStatus::Ambiguous {
            diagnostics.push(DefinitionLookupDiagnostic {
                claim: None,
                kind: "ambiguous_definition".to_string(),
                message: format!(
                    "{} navigation resolved to multiple workspace targets",
                    match operation {
                        NavigationOperation::Declaration => "declaration",
                        NavigationOperation::Definition => "definition",
                    }
                ),
            });
        }
    }

    if structure_unavailable
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC)
    {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC.to_string(),
            message: "one or more C/C++ candidates could not be classified from indexed syntax"
                .to_string(),
        });
    }
    if unproven_link_unit {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC.to_string(),
            message:
                "multiple C/C++ definition bodies remain, but no build graph proves one link unit"
                    .to_string(),
        });
    }
    if truncated {
        diagnostics.push(DefinitionLookupDiagnostic {
            claim: None,
            kind: NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC.to_string(),
            message: format!(
                "{} navigation targets were truncated to the request budget of {}",
                match operation {
                    NavigationOperation::Declaration => "declaration",
                    NavigationOperation::Definition => "definition",
                },
                MAX_NAVIGATION_TARGETS_PER_RESULT
            ),
        });
    }

    NavigationLookupOutcome {
        modeled_definitions,
        status,
        reference,
        targets,
        lexical_definition,
        diagnostics,
        structure_unavailable,
        unproven_link_unit,
        truncated,
        evidence,
    }
}

/// Report `candidates` as an ambiguity the caller must decide, keeping every
/// candidate in the answer.
///
/// An empty candidate set downgrades to `no_definition`, mirroring the same
/// downgrade in [`navigation_lookup_outcome`]: ambiguity means "choose one of
/// these", so an answer with nothing to choose from is a missing answer, not an
/// ambiguous one (#1811).
#[doc(hidden)]
pub fn ambiguous_candidates_outcome(
    candidates: Vec<CodeUnit>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    ambiguous_candidates_outcome_of_kind(candidates, "ambiguous_definition", message)
}

/// Report `candidates` as an ambiguity under a resolver's own diagnostic kind.
///
/// A resolver that names the tier where the tie arose -- Scala's
/// `ambiguous_scala_type`, `ambiguous_scala_enclosing_member`,
/// `ambiguous_scala_named_argument_owner` -- keeps that kind, because it says
/// something the plain kind does not. What it must not keep is an empty answer:
/// the contenders travel with the verdict so a caller, and an audit, can see
/// what the resolver was choosing between (#2167).
#[doc(hidden)]
pub fn ambiguous_candidates_outcome_of_kind(
    mut candidates: Vec<CodeUnit>,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        return no_definition("no_indexed_definition", message);
    }
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Ambiguous,
        reference: None,
        definitions: candidates,
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            claim: None,
            kind: kind.into(),
            message: message.into(),
        }],
    }
}

#[doc(hidden)]
pub fn lexical_definition_outcome(definition: LexicalDefinition) -> DefinitionLookupOutcome {
    let outcome = DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Resolved,
        reference: None,
        definitions: Vec::new(),
        lexical_definition: Some(definition),
        diagnostics: Vec::new(),
    };
    trace::record_selected_lexical(&outcome);
    outcome
}

#[doc(hidden)]
pub fn definition_symbol_key(unit: &CodeUnit) -> (String, String) {
    (unit.fq_name(), format!("{:?}", unit.kind()))
}

/// Emit a confident cross-workspace boundary claim *without* the structural
/// workspace-internal gate. This is the raw emitter; it is `_unchecked` on
/// purpose so that every remaining call site is greppable and must justify why
/// it does not go through [`gated_boundary`].
///
/// Prefer [`gated_boundary`] for any new site: it forces the second, load-
/// bearing question ("does the workspace nonetheless declare this?") to be
/// answered structurally. Only call `boundary_unchecked` when that question is
/// already answered upstream on this path — an exhausted resolver verdict, a
/// preceding enclosing-scope/workspace-namespace probe that returned early, or a
/// predicate that already fused the workspace check. Each such call MUST carry a
/// `// gated upstream:` comment naming where its guard lives.
#[doc(hidden)]
pub fn boundary_unchecked(message: String, claim: UnindexedClaim) -> DefinitionLookupOutcome {
    diagnostic_outcome_with_claim(
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "unresolvable_import_boundary",
        import_boundary_workspace_message(message),
        Some(claim),
    )
}

/// Emit a confident cross-workspace boundary claim only when the target is *not*
/// workspace-internal.
///
/// Every confident `boundary()` claim answers two questions, and the second one
/// is the one call sites keep forgetting:
///
/// 1. Is there an *external signal* — an unresolved import/include/using, a
///    looks-external path? The caller checks this at the call site (it is
///    language- and shape-specific) and only reaches here when it is true.
/// 2. Does the workspace nonetheless *declare or contain* this target — a
///    same-named enclosing-scope member (the #1126 shape) or a workspace
///    namespace/module the qualifier names (the #1089 shape)? If so, the honest
///    outcome is `no_definition`, never a boundary.
///
/// `workspace_internal` answers (2). Routing confident claims through this
/// constructor makes the second check structural instead of a per-site
/// convention: a new emission site cannot skip it, because it cannot reach
/// [`boundary_unchecked`] without supplying the closure. Where both guard
/// families apply, callers `OR` them inside the closure.
/// `claim` is the structured form of the indexing claim the boundary message
/// makes (which unit is asserted external, and in which role), so contract
/// consumers can test the claim without parsing the message.
#[doc(hidden)]
pub fn gated_boundary(
    workspace_internal: impl FnOnce() -> bool,
    boundary_message: String,
    claim: UnindexedClaim,
    no_definition_kind: impl Into<String>,
    no_definition_message: impl Into<String>,
) -> DefinitionLookupOutcome {
    if workspace_internal() {
        no_definition(no_definition_kind, no_definition_message)
    } else {
        trace::record_boundary_gate();
        boundary_unchecked(boundary_message, claim)
    }
}

#[doc(hidden)]
pub fn external_member_boundary_outcome(
    canonical: String,
    message: String,
    mut reference: Option<ResolvedReferenceSite>,
) -> DefinitionLookupOutcome {
    trace::record_named_boundary(canonical.clone());
    if let Some(reference) = &mut reference {
        reference.text = canonical.clone();
    }
    let mut outcome = boundary_unchecked(
        message,
        UnindexedClaim::external_boundary(canonical, ClaimSubjectRole::Member),
    );
    outcome.reference = reference;
    outcome
}

/// Workspace declarations sitting at *exactly* `fqn` but written in a language
/// other than `own_language`.
///
/// Polyglot repositories address one declaration from two languages that share a
/// fully-qualified namespace: Scala names Java types by their exact JVM fq, and
/// pythonnet's Python tests name CLR types by their exact CLR fq
/// (`Python.Test.ClassCtorTest2`).  A language-scoped resolver sees none of
/// those declarations, so without this it cannot tell "not in the workspace"
/// apart from "in the workspace, in another language" — and the confident
/// boundary claim fires for a workspace-indexed target (#1174, same invariant as
/// #1126/#1089).
///
/// Matching is exact-fq only, never normalized and never identifier-level, so a
/// merely same-named declaration in another language can never be produced.
#[doc(hidden)]
pub fn cross_language_declarations(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    own_language: Language,
) -> Vec<CodeUnit> {
    let mut units = support
        .fqn_in_any_language(fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == fqn && language_for_file(unit.source()) != own_language)
        .collect::<Vec<_>>();
    sort_units(&mut units);
    units.dedup();
    units
}

fn import_boundary_workspace_message(message: String) -> String {
    let message = message.replace(
        "outside this partial ",
        "outside the indexed workspace, including this partial ",
    );
    if message.contains("outside the indexed workspace") {
        return message;
    }
    format!(
        "{message}; the imported package, module, namespace, or file may be outside the indexed workspace, including when only a partial workspace is indexed"
    )
}

#[doc(hidden)]
pub fn no_definition(
    kind: impl Into<String>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    diagnostic_outcome(DefinitionLookupStatus::NoDefinition, kind, message)
}

#[doc(hidden)]
pub fn exceeded_budget(
    limit: ReceiverBudgetLimit,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::ExceededBudget(limit),
        "resolution_budget_exceeded",
        message,
    )
}

#[doc(hidden)]
pub fn cancelled(message: impl Into<String>) -> DefinitionLookupOutcome {
    diagnostic_outcome(DefinitionLookupStatus::Cancelled, "cancelled", message)
}

/// Report an ambiguity whose contenders are *not* indexed code units.
///
/// This is the raw emitter; it is named `_without_candidates` on purpose so
/// that every call site is greppable and must justify why the caller is given
/// nothing to choose between. Prefer [`ambiguous_candidates_outcome`] on any
/// path that holds the contenders: an answer a caller can act on beats a status
/// it can only log, and dropping a *proven* candidate here is exactly the C
/// regression in #1811 (2008 of 2010 ambiguous census sites answered with an
/// empty target list).
///
/// It is legitimate only where the ambiguity verdict genuinely arrives without
/// units - a fail-closed `LexicalTypeResolution::Ambiguous`, competing template
/// specialization patterns, semantic-model records, or a provider that
/// deliberately withholds candidate evidence. Each such call site MUST carry a
/// `// no candidates:` comment naming where the contenders were lost.
#[doc(hidden)]
pub fn ambiguous_without_candidates(message: impl Into<String>) -> DefinitionLookupOutcome {
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status: DefinitionLookupStatus::Ambiguous,
        reference: None,
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            claim: None,
            kind: "ambiguous_definition".to_string(),
            message: message.into(),
        }],
    }
}

/// Build an outcome that carries a diagnostic and no definitions.
///
/// Ambiguity has one dedicated emitter each for the with-candidates and
/// without-candidates cases, so this generic constructor never answers
/// [`DefinitionLookupStatus::Ambiguous`]: an ambiguous answer that reaches a
/// caller through an unrelated status helper is the #1811 shape defect.
#[doc(hidden)]
pub fn diagnostic_outcome(
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    diagnostic_outcome_with_claim(status, kind, message, None)
}

/// [`diagnostic_outcome`] plus the structured indexing claim (see
/// [`DefinitionLookupDiagnostic::claim`]).
fn diagnostic_outcome_with_claim(
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
    claim: Option<UnindexedClaim>,
) -> DefinitionLookupOutcome {
    debug_assert!(
        status != DefinitionLookupStatus::Ambiguous,
        "ambiguity is emitted by `ambiguous_candidates_outcome` or `ambiguous_without_candidates`"
    );
    DefinitionLookupOutcome {
        modeled_definitions: Vec::new(),
        status,
        reference: None,
        definitions: Vec::new(),
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
            claim,
        }],
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(test)]
    use brokk_bifrost_test_macros::hardwon;

    #[cfg(test)]
    #[test]
    #[hardwon("#4460: the closed-world guard downgraded structured generated-surface boundaries")]
    fn a_structured_generated_surface_is_an_explicit_closed_world_boundary() {
        assert_eq!(
            rust_closed_world_for_diagnostic_kind(
                RUST_UNSUPPORTED_GENERATED_SURFACE_BOUNDARY_DIAGNOSTIC_KIND,
            ),
            Some(RustClosedWorld::UnsupportedSurface)
        );
    }

    #[cfg(test)]
    #[test]
    #[hardwon(
        "#4460: an inactive cfg module route was downgraded to an actionable incomplete answer"
    )]
    fn an_inactive_cfg_placement_is_an_explicit_closed_world_boundary() {
        assert_eq!(
            rust_closed_world_for_diagnostic_kind("InactiveCfgPlacement"),
            Some(RustClosedWorld::InactiveSelection)
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

/// The incumbent graph retains its own deferred-site resolution authority.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[doc(hidden)]
pub enum DefinitionBatchRoute {
    #[default]
    SelectedNative,
    LegacyUsageGraph,
}

impl DefinitionBatchContext<'_, '_> {
    #[doc(hidden)]
    pub fn route(&self) -> DefinitionBatchRoute {
        self.route
    }
}

pub use crate::analyzer::resolution::diagnostic_kinds::GO_LITERAL_OWNER_UNRESOLVED_DIAGNOSTIC_KIND;
