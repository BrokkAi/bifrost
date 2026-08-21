use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReferenceSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub target: CodeQueryDeclaration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_declaration: Option<CodeQueryDeclaration>,
    pub usage_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_kind: Option<&'static str>,
}

/// One classified identifier position.
///
/// `ast_id` is the content-scoped identity of the underlying facts-arena node
/// and is minted with the same recipe a structural capture uses, so string
/// equality of two `ast_id`s *is* the correlation join between a capture and
/// the occurrence at that node. `id` additionally distinguishes the role, so a
/// node classified twice yields two addressable rows.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryOccurrence {
    pub id: String,
    pub ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub class: &'static str,
    pub role: &'static str,
    pub namespace: &'static str,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    pub raw_spelling: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_spelling: Option<String>,
    pub target: CodeQueryOccurrenceTarget,
}

/// What a reference-class occurrence resolves to. A non-reference row is
/// always `none`, and a reference row never is: `unresolved` carries the exact
/// resolver status so an empty target is never mistaken for "not attempted".
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "target_kind", rename_all = "snake_case")]
pub enum CodeQueryOccurrenceTarget {
    None,
    Resolved {
        units: Vec<CodeQueryDeclaration>,
    },
    Lexical {
        name: String,
        kind: &'static str,
        range: CodeQueryRange,
    },
    Unresolved {
        status: &'static str,
    },
    /// The consumer did not ask for this row's target, so none was attempted.
    /// Distinct from `unresolved`, which is a resolution outcome.
    NotDerived,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub callee_range: CodeQueryRange,
    pub caller: CodeQueryDeclaration,
    pub callee: CodeQueryDeclaration,
    pub call_kind: &'static str,
    pub proof: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<CodeQueryRange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<CodeQueryCallArgument>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallArgument {
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_name: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub variadic: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub spread: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryExpressionSite {
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_name: Option<String>,
    pub caller_fq_name: String,
    pub callee_fq_name: String,
    pub call_range: CodeQueryRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverAnalysis {
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub analysis_kind: &'static str,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub text: String,
    pub input_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<String>,
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<CodeQueryReceiverValue>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub member_targets: Vec<CodeQueryDeclaration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<&'static str>,
}

/// The mandatory terminal row for one receiver/value analysis site. Evidence
/// rows may be empty, but this row always states why and whether that absence
/// is exhaustive.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverOutcome {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub analysis_kind: &'static str,
    pub outcome: &'static str,
    pub coverage: &'static str,
    pub candidate_count: usize,
    pub candidates_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_unsupported: Option<&'static str>,
    pub setup_nodes: usize,
    pub summary_expansions: usize,
    pub scope_nodes: usize,
}

/// The mandatory member-selection summary row for one reference occurrence,
/// projected from the production resolver's own candidate trace. The row
/// exists even when the file records no trace for the occurrence, so an empty
/// candidate relation can never masquerade as a proven-empty selection.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMemberSelection {
    pub id: String,
    /// The occurrence's content-scoped AST identity; joins selection rows to
    /// occurrence and receiver rows without text or range comparison.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// The decoded member spelling at the occurrence.
    pub member: String,
    pub role: &'static str,
    /// `selected`, `unresolved`, or `untraced`.
    pub outcome: &'static str,
    pub selected_count: usize,
    pub candidate_count: usize,
    /// `full`, `selection_only`, or `absent`.
    pub trace_completeness: &'static str,
    /// `exhaustive` for a full trace, `open` for a selection-only trace, and
    /// `unsupported` when the language records no trace at all.
    pub coverage: &'static str,
}

/// The mandatory overload-selection summary for one reference occurrence
/// (#1478 M3).
///
/// Exactly one row exists per occurrence, always. `resolution` states the
/// site's outcome, and it is computed from the verdict counts alone: no
/// permutation of the resolver's candidate order can change it, zero applicable
/// candidates stay `unresolved`, and several equally applicable winners stay
/// `ambiguous` with every candidate row retained. Any candidate whose
/// applicability nobody could decide, a language that does not report the
/// callable axis, and an occurrence with no trace at all all reach
/// `unknown_shape`, so a policy completeness gate turns an exact-cardinality
/// assertion over such a site unreliable instead of clean.
///
/// The site's argument-shape coverage is deliberately not repeated here: it is
/// the `call_shape` row's field, joined on the same `site_ast_id`.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryOverloadSelection {
    pub id: String,
    /// The occurrence's content-scoped AST identity, shared with the
    /// `call_shape`, `callable_applicability`, and occurrence rows.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// `resolved_unique`, `ambiguous`, `unresolved`, or `unknown_shape`.
    pub resolution: &'static str,
    /// Whether the language's resolver reports the callable-applicability axis
    /// at all. `false` forces `resolution` to `unknown_shape`.
    pub supported: bool,
    pub considered_count: usize,
    pub applicable_count: usize,
    pub inapplicable_count: usize,
    /// Candidates whose applicability nobody could decide.
    pub unknown_count: usize,
}

/// One considered candidate's applicability to one call site (#1478 M3).
///
/// One row is one candidate the production resolver actually considered, with
/// the verdict the resolver's own applicability check produced. A refused
/// overload keeps its row and its typed `reason`, which is what makes a losing
/// overload evidence rather than an absence.
///
/// `selected` and `verdict` are independent on purpose, and a policy must read
/// both. No language seam binds a candidate its own check refused, so the
/// wrong-overload signal is the *absence* of a selected applicable candidate at
/// a site that considered some: zero winners means the resolver bound nothing
/// and the site's `overload_selection` summary says `unresolved`. A row that is
/// `selected` with an `unknown` verdict is a third state again -- the seam bound
/// something no applicability check measured.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallableApplicability {
    pub id: String,
    /// The exact `site_ast_id` of the occurrence, and of the
    /// `overload_selection` summary this row was counted in.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    /// The reference occurrence's range: an applicability row explains part of
    /// the resolution of that position.
    pub range: CodeQueryRange,
    /// Position in the resolver's own consideration order, so two otherwise
    /// identical rows stay separately addressable. Never a precedence signal.
    pub ordinal: usize,
    /// `applicable`, `inapplicable`, or `unknown`.
    pub verdict: &'static str,
    /// The typed callable reason, present only when `verdict` is
    /// `inapplicable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The precedence tier the resolver considered the candidate at. Absent is
    /// unattributed, never weakest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    pub selected: bool,
    /// What the resolver considered. A lexical binder or an external route is
    /// something the resolver weighed but is not a callable declaration.
    pub candidate: CodeQueryCandidateRef,
}

/// The mandatory terminal row for one bounded-dispatch site (#1477 M4).
///
/// Exactly one row exists per input site. Target rows may be empty, but this
/// row always states the semantic outcome that produced that emptiness and
/// whether the retained target set is exhaustive. `coverage` is `exhaustive`
/// only when the workspace oracle itself reported exhaustive coverage across
/// every located call site and every target set; an unknown, unsupported,
/// over-budget, or cancelled dispatch is never exhaustive, so a policy
/// completeness gate turns an exact-set assertion over such a site unreliable
/// instead of clean.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDispatchOutcome {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// The `SemanticOutcome` variant the dispatch seam published:
    /// `resolved`, `ambiguous`, `unproven`, `unknown`, `unsupported`,
    /// `exceeded_budget`, or `cancelled`.
    pub outcome: &'static str,
    /// The oracle's own `CandidateCoverage`: `exhaustive`, `open`, or
    /// `truncated`.
    pub coverage: &'static str,
    /// Exact semantic call sites located inside the input range. Zero means
    /// the position holds no call the semantic artifact retained, which is
    /// why the outcome is `unknown` rather than a proven-empty target set.
    pub call_site_count: usize,
    /// Retained target rows for this site, counting boundary arms that name a
    /// target as well as materialized candidates.
    pub target_count: usize,
    pub targets_truncated: bool,
    /// The unsupported semantic capability, when the outcome is `unsupported`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_unsupported: Option<&'static str>,
    /// The exceeded semantic budget dimension, when the outcome is
    /// `exceeded_budget`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceeded_limit: Option<&'static str>,
}

/// One bounded dispatch arm of one call site (#1477 M4).
///
/// A row is either a materialized candidate (`boundary_kind` absent) or a
/// boundary arm the oracle named a target for (`boundary_kind` present, and
/// the workspace holds no body to render). `proof` and `completeness` are the
/// oracle's own per-arm quality; `coverage` is the site's candidate coverage.
/// `dispatch` is the honest conjunction of those three axes and never
/// upgrades: it is `proven_dispatch` only for a proven, complete arm inside an
/// exhaustive set, and `may_dispatch` otherwise. The three fields are kept
/// separate so an assertion can read either the conjunction or the exact axis
/// that made an arm open.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryDispatchTarget {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    /// Zero-based position of this arm among the site's retained arms.
    pub ordinal: usize,
    /// The arm's semantic identity: a domain-separated digest over the
    /// target's artifact fingerprint and semantic locator. Never an arena id.
    pub target_id: String,
    /// The workspace-relative path the target locator names.
    pub target_path: String,
    /// The target rendered as a workspace declaration, when the workspace can
    /// still locate one for the exact procedure. Absent for an external or
    /// unmaterialized arm, and for a materialized procedure whose declaration
    /// the workspace no longer indexes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_declaration: Option<CodeQueryDeclaration>,
    /// `proven` or `unproven`, exactly as the dispatch oracle stated it.
    pub proof: &'static str,
    /// `complete` or `partial`, exactly as the dispatch oracle stated it.
    pub completeness: &'static str,
    /// The owning site's candidate coverage, repeated on the arm so a target
    /// row alone is enough to reject an exact-set claim.
    pub coverage: &'static str,
    /// `proven_dispatch` or `may_dispatch`.
    pub dispatch: &'static str,
    /// The typed boundary kind, when this arm is a boundary rather than a
    /// materialized candidate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary_kind: Option<&'static str>,
}

/// The mandatory terminal row for one member's canonical method family
/// (#1477 M4).
///
/// Exactly one row exists per member input. Edge rows may be empty, and this
/// row is what says why: a `proven` family with no edge overrides and
/// implements nothing, a `no_family` member is one the language excludes
/// outright (a constructor, a static method, a private method, or a
/// declaration that is not a method), while `incomplete` and `unsupported`
/// are honest failures that carry no family id. `coverage` is `exhaustive`
/// only for the two complete answers, so an exact-set assertion over an
/// unproven member turns unreliable rather than clean.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMemberFamily {
    pub id: String,
    /// The member's structured canonical identity digest -- the same recipe
    /// candidate rows use for `canonical_member_id`, never a rendered FQN.
    pub member_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<CodeQueryDeclaration>,
    /// `proven`, `no_family`, `incomplete`, or `unsupported`.
    pub outcome: &'static str,
    /// Why the outcome is not `proven`. A proven family states none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The measured strength of the analyzer's member-identity evidence for
    /// this member's language.
    pub capability: &'static str,
    /// `exhaustive` or `open`.
    pub coverage: &'static str,
    /// The canonical family id: a domain-separated digest over the
    /// deterministically ordered exact family roots *of this member* plus
    /// language identity. Two members carry the same id exactly when their
    /// proven root closures coincide, so a member that redeclares several roots
    /// (a class implementing two interfaces that each declare the member) has a
    /// different id from any one of those roots. Read it as "answers to the
    /// same contracts", not as a connected-component id. Absent whenever the
    /// family is not proven.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    pub overrides_count: usize,
    pub implements_count: usize,
    pub overridden_by_count: usize,
    pub implemented_by_count: usize,
    pub edge_count: usize,
    /// How many exact roots the family id digested.
    pub root_count: usize,
}

/// One typed edge of one member's method family (#1477 M4).
///
/// Forward rows (`overrides`, `implements`) are the analyzer's direct proof.
/// Inverse rows (`overridden_by`, `implemented_by`) are the bounded inversion
/// of those same forward edges, never an independent resolution, so the *edge*
/// round-trips: the same two declarations appear from either end, with the
/// relation reversed.
///
/// `family_id` is the id of the row's own member, not of the edge. It matches
/// from both ends whenever both members prove the same root closure -- an
/// override chain, for example. It differs when they do not, as when the
/// overriding member also implements a second interface that declares the same
/// contract.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryMemberFamilyEdge {
    pub id: String,
    /// The source member's canonical identity digest.
    pub member_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    /// Zero-based position among this member's retained edges: forward edges
    /// first, then inverse edges, each ordered by target identity.
    pub ordinal: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CodeQueryDeclaration>,
    /// The target member's canonical identity digest.
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQueryDeclaration>,
    /// `overrides`, `implements`, `overridden_by`, or `implemented_by`.
    pub relation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
    /// Hierarchy hops between the two owners on the route that found the edge.
    pub hierarchy_depth: usize,
    /// `proven` when the ancestor held exactly one member of that name and
    /// recorded arity, so structure alone singled the target out. `unproven`
    /// when only the recorded parameter-type spellings separated an overload
    /// set: a spelling is not a resolved or erased type.
    pub proof: &'static str,
    /// `complete`. An edge row is only ever emitted from a fully enumerated
    /// family, because a truncated walk reports `incomplete` and no edges. The
    /// axis is published anyway so a policy reads one proof/completeness
    /// vocabulary across the dispatch and family row families.
    pub completeness: &'static str,
    /// The owning member's family coverage, repeated on the edge so an edge
    /// row alone is enough to reject an exact-set claim.
    pub coverage: &'static str,
}

/// One typed receiver value retained for a site. Nested factory returns are
/// flattened into a parent-linked chain instead of nested presentation data.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryReceiverEvidence {
    pub id: String,
    pub site_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_ast_id: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_evidence_id: Option<String>,
    pub ordinal: usize,
    pub chain_hop: usize,
    pub evidence_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_fq_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declaration_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_id: Option<String>,
    pub proof: &'static str,
    pub completeness: &'static str,
}

/// The mandatory structured call-shape outcome row for one exact call site.
/// Group and argument rows may be empty, but this row always states the
/// call kind and how much of the shape the analyzer could see.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallShape {
    pub id: String,
    pub site_id: String,
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_range: Option<CodeQueryRange>,
    pub call_kind: &'static str,
    pub coverage: &'static str,
    pub group_count: usize,
}

/// One ordered argument-list group of a call shape.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallArgumentGroup {
    pub id: String,
    pub site_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    pub group_index: usize,
    pub kind: &'static str,
    pub argument_count: usize,
}

/// One ordered argument inside one argument-list group.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallShapeArgument {
    pub id: String,
    pub group_id: String,
    pub site_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    pub argument_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub spread: bool,
}

/// One normalized actual-to-formal binding of one exact call site (#2438).
///
/// The row bridges the two halves of Bifrost's call evidence: `site_id`,
/// `group_id` and `argument_id` are the facts-arena call-shape identities, and
/// `formal_index`/`formal_name` are what the shared formal-slot matcher bound
/// the actual to. A policy therefore reaches "the actual passed to formal
/// `timeout` of this exact callable" by joining ids, never by comparing ranges
/// or callee text.
///
/// At least one row exists per call shape. `terminal` marks the row that states
/// the call's status when no pair could be produced -- an unreadable shape, an
/// unresolved or ambiguous callee, unrecorded formals, or a call that passes
/// nothing at all. Zero rows is therefore never a claim that a call binds no
/// argument.
///
/// `mapping` is this row's own certainty and `coverage` is the whole call's
/// partition coverage, repeated on every row so one row alone is enough to
/// reject an exact-set claim over the call's arguments.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallBinding {
    pub id: String,
    /// The owning `call_shape` row's site identity.
    pub site_id: String,
    /// The facts-arena AST identity of the call node, so a binding row joins an
    /// occurrence or dispatch row without comparing positions.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    /// The actual's own span, or the whole call's span on a terminal row.
    pub range: CodeQueryRange,
    /// The `call_argument_group` row of the actual.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// The `call_argument` row of the actual. Absent on a terminal row and on
    /// a defaulted formal, neither of which has a source actual.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument_id: Option<String>,
    /// The exact callee declaration the production resolver named, when the
    /// workspace still indexes a range for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<CodeQueryDeclaration>,
    /// The `callable_signature` row this binding selects, when the target
    /// publishes exactly one signature entry. Absent for an overload set, which
    /// this slice does not choose between.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_id: Option<String>,
    /// The actual's position inside its own argument-list group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_index: Option<usize>,
    /// The parameter name written at the call site, when one was written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_name: Option<String>,
    /// Zero-based position of the bound formal in the callable's ordinary
    /// (non-receiver) parameter list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_index: Option<usize>,
    /// The bound formal's canonical declared name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formal_name: Option<String>,
    /// `positional`, `named`, `defaulted`, `variadic`, `spread`, `receiver`, or
    /// `implicit`. Absent on a terminal row, which binds nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_kind: Option<&'static str>,
    /// `exact`, `ambiguous`, `incomplete`, or `unsupported`.
    pub mapping: &'static str,
    /// The typed reason this row is not `exact`. An exact row states none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The whole call's partition coverage: `exhaustive`, `partial`,
    /// `unknown`, or `unsupported`.
    pub coverage: &'static str,
    /// Actual argument rows the call shape enumerated.
    pub actual_count: usize,
    /// Actuals bound to a formal with an exact mapping.
    pub bound_count: usize,
    pub terminal: bool,
}

/// One source-derived direct effect of one exact call site (#2437).
///
/// The row states that an activated semantic-model pack declares `effect_id`
/// for the callee this call's dispatch answer named. Nothing about the effect
/// is inferred from source text: `proof` and `coverage` are the dispatch
/// oracle's own words, and `timing`, `certainty` and the pack provenance are
/// the reviewed declaration's.
///
/// At least one row exists per call site. `terminal` marks the row that states
/// the site's status when no declaration applies — a call whose callee nobody
/// models, whose dispatch is open, or whose target identity could not be
/// built. Zero rows is therefore never a claim that a call has no effect.
///
/// `coverage` is repeated on every row of the site, so one row alone is enough
/// to reject an "this call performs no such effect" claim.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallEffect {
    pub id: String,
    /// The owning `call_shape` row's site identity.
    pub site_id: String,
    /// The facts-arena AST identity of the call node, so an effect row joins an
    /// occurrence or dispatch row without comparing positions.
    pub site_ast_id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// Equal to `dispatch_target.target_id` for the arm this row came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// The callee rendered as a workspace declaration, when the workspace
    /// indexes one for the arm's target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee: Option<CodeQueryDeclaration>,
    /// The canonical modeled identity the declaration lookup used, spelled
    /// `owner.member/arity[+recv]`. Absent when no identity could be built.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_symbol: Option<String>,
    /// The namespaced effect the pack declares. Absent on a terminal row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// Always `direct` on this domain; transitive attribution lives on
    /// `procedure_effect`.
    pub classification: &'static str,
    /// `immediate`, `deferred`, or `unknown`, from the declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<&'static str>,
    /// `definite` or `possible`: the meet of the declaration's own certainty
    /// and the dispatch arm's proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty: Option<&'static str>,
    /// `proven` or `unproven`, copied from the dispatch arm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<&'static str>,
    /// `declared`, `none`, `incomplete`, or `unsupported`.
    pub derivation: &'static str,
    /// The typed reason the derivation is not exhaustive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The site's effect coverage: `exhaustive`, `open`, `truncated`, or
    /// `unsupported`.
    pub coverage: &'static str,
    /// The activated pack that published the declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    /// The pack's own model identity for the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    /// The compiled procedure summary the declaration rides on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_id: Option<String>,
    /// Dispatch arms the site published.
    pub arm_count: usize,
    /// Arms a unique activated summary modeled.
    pub modeled_arm_count: usize,
    pub terminal: bool,
}

/// One effect attributed to one procedure, direct or transitive (#2437).
///
/// Computed by a bounded deterministic fixpoint over the procedure's reachable
/// call graph, using the same dispatch answers `call_effect` publishes. The
/// witness columns are the source-backed chain from this procedure to the exact
/// call that carries the declared effect: `witness_site_id` is the first hop and
/// `witness_effect_site_id` is the declaring call, and both are `call_shape`
/// site identities, so a reader joins them to `call_effect` by id.
///
/// At least one row exists per procedure, so zero rows is never a claim that a
/// procedure is effect-free. `coverage` states whether an absence of rows for a
/// given effect is a proof or only a silence.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryProcedureEffect {
    pub id: String,
    /// Equal to the `declaration` domain's `id` for the same procedure.
    pub procedure_id: String,
    pub procedure_name: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    /// The namespaced effect. Absent on a terminal row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect_id: Option<String>,
    /// `direct` when the declaring procedure is this one or a callee written in
    /// its own body, `transitive` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<&'static str>,
    /// `definite` or `possible`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certainty: Option<&'static str>,
    /// `immediate`, `deferred`, or `unknown`. A path through a deferred
    /// declaration keeps the deferred timing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<&'static str>,
    /// Call hops from this procedure to the declaring one. `0` means the pack
    /// declares the effect on this procedure itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// `declared`, `none`, `incomplete`, or `unsupported`.
    pub derivation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// `exhaustive`, `open`, `truncated`, or `unsupported`, for the whole
    /// reachable call graph of this procedure.
    pub coverage: &'static str,
    /// Whether a witness chain is retained for this row.
    pub witness_available: bool,
    /// Retained hops in the witness chain.
    pub witness_steps: usize,
    /// The `call_shape` site identity of the first hop out of this procedure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_site_id: Option<String>,
    /// The `call_shape` site identity of the call that carries the declared
    /// effect, which joins `call_effect.site_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_effect_site_id: Option<String>,
    /// The bounded rendered chain, `caller -> ... -> declaring procedure`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_chain: Option<String>,
    /// Whether the chain hit the retained-step bound.
    pub witness_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_id: Option<String>,
    pub terminal: bool,
}

/// The mandatory row for one persisted signature entry of one declaration
/// (#1478 M2).
///
/// Projected from the analyzer's own `SignatureMetadata`, never re-parsed, so
/// a warm cache and a cold run agree by construction. Exactly one row exists
/// per persisted entry, and a declaration whose language publishes no metadata
/// at all still gets one row whose `coverage` is `unrecorded` -- zero
/// parameter rows can therefore never be read as a proven-empty parameter
/// list. An overload set that shares one fully qualified name separates into
/// one row per overload, distinguished by `ordinal`.
///
/// A fact the adapter did not record is absent, never defaulted. The arity
/// fields are absent when the language records no arity, and
/// `receiver_contract` is absent when the adapter never inspected modifiers,
/// because "not static" and "nobody looked" are different answers.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryCallableSignature {
    pub id: String,
    pub path: String,
    pub language: &'static str,
    pub range: CodeQueryRange,
    pub declaration: CodeQueryDeclaration,
    /// Zero-based position among the declaration's persisted signature
    /// entries.
    pub ordinal: usize,
    /// `exact`, `arity_unrecorded`, or `unrecorded`.
    pub coverage: &'static str,
    /// `function`, `method`, `constructor`, `field`, `class`, `module`,
    /// `macro`, or `file_scope`.
    pub role: &'static str,
    /// The rendered signature header the adapter published. Evidence for a
    /// human reading a finding; never parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// How many arguments a call must supply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_arity: Option<usize>,
    /// How many arguments the declaration accepts, ignoring repetition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_arity: Option<usize>,
    /// Whether the trailing parameter repeats, so a call may exceed
    /// `total_arity`.
    pub repeated: bool,
    /// Declared type parameters.
    pub generic_arity: usize,
    /// `none`, `instance`, `static_or_companion`, or `extension`, when the
    /// persisted facts decide it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_contract: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    /// Whether this entry is a declaration without a body.
    pub declaration_only: bool,
    pub parameter_count: usize,
}

/// One ordered declared parameter of one callable signature (#1478 M2).
///
/// `range` is the *declaration's* range, because the persisted contract
/// anchors a parameter only inside the rendered signature label; that anchor is
/// published as `label_start_byte`/`label_end_byte` under its own name so it is
/// never mistaken for a file offset.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQuerySignatureParameter {
    pub id: String,
    pub signature_id: String,
    pub path: String,
    pub range: CodeQueryRange,
    pub parameter_index: usize,
    /// The parameter label the adapter recorded.
    pub label: String,
    /// The declared type spelling, when the adapter records per-parameter
    /// types. A spelling discriminates inside an already bounded candidate
    /// set; it is not a resolved type identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_type: Option<String>,
    /// Whether a call may omit this parameter. Absent when the signature
    /// records no arity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    /// Whether this is the repeating trailing parameter. Absent when the
    /// signature records no arity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repeated: Option<bool>,
    pub label_start_byte: usize,
    pub label_end_byte: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "receiver_value_kind", rename_all = "snake_case")]
pub enum CodeQueryReceiverValue {
    AllocationSite {
        type_declaration: CodeQueryDeclaration,
        allocation_site: CodeQuerySourceSite,
    },
    InstanceType {
        declaration: CodeQueryDeclaration,
    },
    ClassOrStaticObject {
        declaration: CodeQueryDeclaration,
    },
    ModuleOrExportObject {
        declaration: CodeQueryDeclaration,
    },
    CurrentReceiver {
        declaration: CodeQueryDeclaration,
    },
    FactoryReturn {
        factory: CodeQueryDeclaration,
        returned_value: Box<CodeQueryReceiverValue>,
    },
}

impl CodeQueryReceiverValue {
    pub fn render_text(&self) -> String {
        match self {
            Self::AllocationSite {
                type_declaration,
                allocation_site,
            } => format!(
                "allocation {} at {}:{}:{}",
                type_declaration.fq_name,
                allocation_site.path,
                allocation_site.range.start_line,
                allocation_site.range.start_column
            ),
            Self::InstanceType { declaration } => {
                format!("instance {}", declaration.fq_name)
            }
            Self::ClassOrStaticObject { declaration } => {
                format!("class/static {}", declaration.fq_name)
            }
            Self::ModuleOrExportObject { declaration } => {
                format!("module/export {}", declaration.fq_name)
            }
            Self::CurrentReceiver { declaration } => {
                format!("current receiver {}", declaration.fq_name)
            }
            Self::FactoryReturn {
                factory,
                returned_value,
            } => format!(
                "factory {} -> {}",
                factory.fq_name,
                returned_value.render_text()
            ),
        }
    }
}

impl CodeQueryReceiverAnalysis {
    pub fn render_detail_lines(&self) -> Vec<String> {
        let mut lines = self
            .values
            .iter()
            .map(|value| format!("value -> {}", value.render_text()))
            .collect::<Vec<_>>();
        lines.extend(
            self.member_targets
                .iter()
                .map(|target| format!("member -> {}", target.fq_name)),
        );
        if let Some(reason) = self.reason {
            lines.push(format!("reason -> {reason}"));
        }
        if let Some(limit) = self.limit {
            lines.push(format!("limit -> {limit}"));
        }
        lines
    }
}
