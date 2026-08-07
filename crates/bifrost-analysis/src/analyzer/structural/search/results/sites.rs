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
