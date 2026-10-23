use super::read_source;
use crate::analyzer::common::language_for_file;
use crate::analyzer::languages::{BoundedReceiverQuery, language_support_for_hook};
use crate::analyzer::usages::get_definition::{BoundedResolution, parse_tree_for_language};
use crate::analyzer::usages::receiver_analysis::{
    INTERACTIVE_TYPE_LOOKUP_BUDGET, ReceiverAnalysisBudget, ReceiverBudgetLimit,
};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, SourceLocationRequest, resolve_reference_site,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{AnalyzerDefinitionLookup, CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
use std::sync::Arc;
use tree_sitter::Tree;

#[derive(Debug, Clone)]
pub struct TypeLookupRequest {
    pub file: ProjectFile,
    pub source: Option<Arc<String>>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct TypeLookupOutcome {
    #[doc(hidden)]
    pub status: TypeLookupStatus,
    #[doc(hidden)]
    pub reference: Option<ResolvedReferenceSite>,
    pub types: Vec<TypeLookupType>,
    #[doc(hidden)]
    pub diagnostics: Vec<TypeLookupDiagnostic>,
    pub target_kind: TypeLookupTargetKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TypeLookupStatus {
    Resolved,
    Unavailable,
    /// Resolution produced a source-backed partial answer, but the resolver
    /// could not establish an exhaustive result. This is not a proven absence
    /// and must never be projected as a precise singleton.
    Incomplete,
    /// Resolution was stopped by an operational cancellation request.
    Cancelled,
    NoType,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
    /// Bounded resolution stopped on the named budget axis before finishing.
    /// An incomplete answer, not a proven "no type": the workspace may still
    /// hold a type for the reference.
    ExceededBudget(ReceiverBudgetLimit),
}

impl TypeLookupStatus {
    #[doc(hidden)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unavailable => "unavailable",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::NoType => "no_type",
            Self::Ambiguous => "ambiguous",
            Self::UnsupportedLanguage => "unsupported_language",
            Self::InvalidLocation => "invalid_location",
            Self::NotFound => "not_found",
            Self::ExceededBudget(_) => "exceeded_budget",
        }
    }
}

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct TypeLookupDiagnostic {
    #[doc(hidden)]
    pub kind: String,
    #[doc(hidden)]
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TypeLookupType {
    pub fqn: String,
    pub definitions: Vec<CodeUnit>,
    /// Exact active semantic-model record used to produce this type, when the
    /// type has no workspace declaration. Keep the record identity beside the
    /// synthetic compatibility declaration so downstream member resolution
    /// never reconstructs provenance from a rendered FQN.
    pub semantic_model_id: Option<String>,
}

/// Project one exact semantic-model type record into the compatibility type
/// lookup domain. The synthetic declaration is only a DTO carrier; callers
/// must retain `semantic_model_id` and use it for identity-sensitive work.
#[doc(hidden)]
pub fn semantic_model_lookup_type(
    file: &ProjectFile,
    symbol: &crate::analyzer::semantic_model::SemanticModelSymbol,
) -> TypeLookupType {
    TypeLookupType {
        fqn: symbol.qualified_name.clone(),
        definitions: vec![CodeUnit::with_signature(
            file.clone(),
            crate::analyzer::CodeUnitType::Class,
            "",
            symbol.qualified_name.clone(),
            symbol.signature.clone(),
            true,
        )],
        semantic_model_id: Some(symbol.id.clone()),
    }
}

#[doc(hidden)]
pub fn exact_semantic_model_type_outcome(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    language: Language,
    fqn: &str,
    target_kind: TypeLookupTargetKind,
) -> Option<TypeLookupOutcome> {
    let overlay = analyzer.semantic_model_overlay()?;
    let matched = overlay.symbols_named(fqn);
    let matched_record_count = matched.records.len();
    let records = matched
        .records
        .into_iter()
        .filter(|symbol| {
            symbol.owner_id.is_none()
                && symbol.language == language.config_label()
                && (symbol.qualified_name == fqn || symbol.aliases.iter().any(|alias| alias == fqn))
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return None;
    }
    let complete = matched.disposition
        == crate::analyzer::semantic_model::SemanticModelOverlayDisposition::Unique
        && matched_record_count == 1
        && records.len() == 1
        && !records[0].provenance.ambiguous
        && records[0].provenance.completeness
            == crate::analyzer::semantic_model::SemanticModelCompleteness::Complete;
    let types = records
        .into_iter()
        .map(|symbol| semantic_model_lookup_type(file, symbol))
        .collect();
    Some(TypeLookupOutcome {
        status: if complete {
            TypeLookupStatus::Resolved
        } else {
            TypeLookupStatus::Ambiguous
        },
        reference: None,
        types,
        diagnostics: if complete {
            Vec::new()
        } else {
            vec![TypeLookupDiagnostic {
                kind: "semantic_model_type_incomplete".to_string(),
                message: format!(
                    "semantic-model declarations for `{fqn}` are partial or ambiguous"
                ),
            }]
        },
        target_kind,
    })
}

pub fn resolve_type_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<TypeLookupRequest>,
) -> Vec<TypeLookupOutcome> {
    resolve_type_batch_with_budget(analyzer, requests, INTERACTIVE_TYPE_LOOKUP_BUDGET)
}

#[doc(hidden)]
pub fn resolve_type_batch_with_budget(
    analyzer: &dyn IAnalyzer,
    requests: Vec<TypeLookupRequest>,
    budget: ReceiverAnalysisBudget,
) -> Vec<TypeLookupOutcome> {
    let mut context = TypeBatchContext::new(analyzer);
    requests
        .into_iter()
        .map(|request| resolve_one(analyzer, &mut context, request, budget))
        .collect()
}

/// Resolve a caller-selected structured reference site without applying the
/// editor selection/token expansion contract. Callers must supply the exact
/// source and its corresponding parsed tree; this entry point validates those
/// inputs before entering the same bounded language dispatch as batch lookup.
#[doc(hidden)]
pub fn resolve_type_at_reference_site_with_budget(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
) -> TypeLookupOutcome {
    if let Err(message) = validate_caller_reference_site(file, source, tree, &site) {
        return diagnostic_outcome(
            TypeLookupStatus::InvalidLocation,
            "invalid_location",
            message,
        );
    }
    let language = language_for_file(file);
    let support = AnalyzerDefinitionLookup::new(analyzer, language);
    finish_bounded_resolution(
        bounded_type_resolution(
            analyzer, &support, file, language, source, tree, &site, budget,
        ),
        language,
        site,
    )
}

struct TypeBatchContext<'a> {
    sources: HashMap<ProjectFile, Result<Arc<String>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    support: AnalyzerDefinitionLookup<'a>,
}

impl<'a> TypeBatchContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            sources: HashMap::default(),
            trees: HashMap::default(),
            support: AnalyzerDefinitionLookup::new(analyzer, Language::None),
        }
    }

    fn source(&mut self, file: &ProjectFile) -> Result<Arc<String>, String> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| read_source(file).map(Arc::new))
            .clone()
    }

    fn tree(&mut self, file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
        self.trees
            .entry((file.clone(), language))
            .or_insert_with(|| parse_tree_for_type_lookup(file, language, source))
            .clone()
    }
}

fn resolve_one<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut TypeBatchContext<'a>,
    request: TypeLookupRequest,
    budget: ReceiverAnalysisBudget,
) -> TypeLookupOutcome {
    let file = request.file.clone();
    let language = language_for_file(&file);
    let source = match request.source.clone() {
        Some(source) => source,
        None => match context.source(&file) {
            Ok(source) => source,
            Err(message) => {
                return diagnostic_outcome(TypeLookupStatus::NotFound, "file_read_failed", message);
            }
        },
    };
    let tree = if request.source.is_some() {
        parse_tree_for_type_lookup(&file, language, &source)
    } else {
        context.tree(&file, language, &source)
    };
    let site = match resolve_reference_site(
        &request.as_source_location(),
        &source,
        tree.as_ref().map(Tree::root_node),
    ) {
        Ok(site) => site,
        Err(message) => {
            return diagnostic_outcome(
                TypeLookupStatus::InvalidLocation,
                "invalid_location",
                message,
            );
        }
    };

    finish_bounded_resolution(
        bounded_type_resolution(
            analyzer,
            &context.support,
            &file,
            language,
            &source,
            tree.as_ref(),
            &site,
            budget,
        ),
        language,
        site,
    )
}

fn finish_bounded_resolution(
    resolution: Option<BoundedResolution<TypeLookupOutcome>>,
    language: Language,
    site: ResolvedReferenceSite,
) -> TypeLookupOutcome {
    let Some(resolution) = resolution else {
        return finish_lookup_outcome(
            diagnostic_outcome(
                TypeLookupStatus::UnsupportedLanguage,
                "unsupported_language",
                format!("{language:?} type lookup is not implemented yet"),
            ),
            site,
        );
    };
    let outcome = match resolution {
        BoundedResolution::Complete { value, .. } => value,
        BoundedResolution::Exceeded { limit, .. } => diagnostic_outcome(
            TypeLookupStatus::ExceededBudget(limit),
            "resolution_budget_exhausted",
            format!(
                "bounded type resolution stopped after exhausting its {} budget; \
                 the result is incomplete, not a proven absence of a type",
                limit.as_str()
            ),
        ),
        BoundedResolution::Cancelled { .. } => diagnostic_outcome(
            TypeLookupStatus::Cancelled,
            "cancelled",
            "bounded type resolution was cancelled before it completed",
        ),
    };
    finish_lookup_outcome(outcome, site)
}

#[doc(hidden)]
pub fn validate_caller_reference_site(
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> Result<(), String> {
    if site.path != rel_path_string(file) {
        return Err("reference path does not match the requested file".to_string());
    }
    let range = &site.range;
    if range.start_byte >= range.end_byte || range.end_byte > source.len() {
        return Err(format!(
            "invalid byte range [{}, {}) for {} byte file",
            range.start_byte,
            range.end_byte,
            source.len()
        ));
    }
    if !source.is_char_boundary(range.start_byte) || !source.is_char_boundary(range.end_byte) {
        return Err(format!(
            "byte range [{}, {}) does not align to UTF-8 character boundaries",
            range.start_byte, range.end_byte
        ));
    }
    if site.focus_start_byte >= site.focus_end_byte
        || site.focus_start_byte < range.start_byte
        || site.focus_end_byte > range.end_byte
        || !source.is_char_boundary(site.focus_start_byte)
        || !source.is_char_boundary(site.focus_end_byte)
    {
        return Err("reference focus is empty, invalid, or outside its range".to_string());
    }
    if source.get(range.start_byte..range.end_byte) != Some(site.text.as_str()) {
        return Err("reference text does not match the supplied source range".to_string());
    }
    if let Some(tree) = tree {
        let root = tree.root_node();
        // Grammars may exclude leading or trailing trivia from the root.
        if root.end_byte() > source.len()
            || root.start_byte() > range.start_byte
            || root.end_byte() < range.end_byte
        {
            return Err(
                "parsed tree is outside the supplied source or does not cover the reference"
                    .to_string(),
            );
        }
        let node = root
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            .ok_or_else(|| "reference range is not covered by parsed syntax".to_string())?;
        if node.start_byte() > range.start_byte
            || node.end_byte() < range.end_byte
            || node.start_byte() > site.focus_start_byte
            || node.end_byte() < site.focus_end_byte
        {
            return Err("reference range and focus are not covered by one named node".to_string());
        }
    }
    Ok(())
}

/// One location's type, resolved through the bounded receiver contract, or
/// `None` when no route serves the language at all.
///
/// The structural-receiver resolver is the primary route: the same bounded core
/// the receiver query dispatches through answers here under the caller's
/// budget. Java and JS/TS keep their own bounded arms because their receiver
/// analysis runs elsewhere (a Java resolution session, the JS/TS syntax index).
/// Every arm takes the same budget; no arm runs unbounded.
#[allow(clippy::too_many_arguments)]
fn bounded_type_resolution(
    analyzer: &dyn IAnalyzer,
    support: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
) -> Option<BoundedResolution<TypeLookupOutcome>> {
    language_support_for_hook(language, "parse_tree_for_type_lookup")?.bounded_type_resolution(
        support,
        language,
        BoundedReceiverQuery {
            analyzer,
            file,
            source,
            tree,
            site,
            budget,
            cancellation: None,
        },
    )
}

fn finish_lookup_outcome(
    mut outcome: TypeLookupOutcome,
    site: ResolvedReferenceSite,
) -> TypeLookupOutcome {
    outcome.reference = Some(site);
    outcome
}

impl TypeLookupRequest {
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

#[doc(hidden)]
pub fn parse_tree_for_type_lookup(
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    match language_support_for_hook(language, "parse_tree_for_type_lookup") {
        Some(support) => support.parse_tree_for_type_lookup(file, language, source),
        None => parse_tree_for_language(file, language, source),
    }
}

#[doc(hidden)]
pub fn candidates_outcome(fqn: impl Into<String>, candidates: Vec<CodeUnit>) -> TypeLookupOutcome {
    candidates_outcome_with_target_kind(fqn, candidates, TypeLookupTargetKind::ValueExpression)
}

#[doc(hidden)]
pub fn type_reference_outcome(
    fqn: impl Into<String>,
    candidates: Vec<CodeUnit>,
) -> TypeLookupOutcome {
    candidates_outcome_with_target_kind(fqn, candidates, TypeLookupTargetKind::TypeReference)
}

#[doc(hidden)]
pub fn candidates_outcome_with_target_kind(
    fqn: impl Into<String>,
    mut candidates: Vec<CodeUnit>,
    target_kind: TypeLookupTargetKind,
) -> TypeLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    let mut semantic_keys = HashSet::default();
    for candidate in &candidates {
        semantic_keys.insert((candidate.fq_name(), candidate.source().clone()));
    }
    let status = if semantic_keys.len() <= 1 {
        TypeLookupStatus::Resolved
    } else {
        TypeLookupStatus::Ambiguous
    };
    candidates_outcome_with_status(fqn, candidates, status, target_kind)
}

#[doc(hidden)]
pub fn candidates_outcome_with_status(
    fqn: impl Into<String>,
    candidates: Vec<CodeUnit>,
    status: TypeLookupStatus,
    target_kind: TypeLookupTargetKind,
) -> TypeLookupOutcome {
    TypeLookupOutcome {
        status,
        reference: None,
        types: vec![TypeLookupType {
            fqn: fqn.into(),
            definitions: candidates,
            semantic_model_id: None,
        }],
        diagnostics: if status == TypeLookupStatus::Ambiguous {
            vec![TypeLookupDiagnostic {
                kind: "ambiguous_type".to_string(),
                message: "reference resolved to multiple possible types".to_string(),
            }]
        } else {
            Vec::new()
        },
        target_kind,
    }
}

#[doc(hidden)]
pub fn no_type(kind: impl Into<String>, message: impl Into<String>) -> TypeLookupOutcome {
    diagnostic_outcome(TypeLookupStatus::NoType, kind, message)
}

#[doc(hidden)]
pub fn diagnostic_outcome(
    status: TypeLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> TypeLookupOutcome {
    TypeLookupOutcome {
        status,
        reference: None,
        types: Vec::new(),
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
        target_kind: TypeLookupTargetKind::ValueExpression,
    }
}

#[doc(hidden)]
pub fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        left.fq_name()
            .cmp(&right.fq_name())
            .then_with(|| left.source().cmp(right.source()))
    });
}

#[doc(hidden)]
pub fn projection_target_kind(
    projections: &[crate::analyzer::resolution::LoweredBindingProjection],
) -> (
    TypeLookupTargetKind,
    Option<BindingProjectionKind>,
    Vec<BindingProjectionKind>,
) {
    let mut kinds = Vec::new();
    for kind in projections.iter().map(|projection| projection.kind()) {
        // These outputs serve impl ownership and field lookup. They do not
        // compete with the source expression's public type projection.
        if matches!(
            kind,
            BindingProjectionKind::TargetNominalTypeIdentity
                | BindingProjectionKind::TargetMemberOwnerType
        ) {
            continue;
        }
        if !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    let selected = if kinds.iter().any(|kind| kind.is_callable_result()) {
        Some(BindingProjectionKind::TargetCallableResultType)
    } else if kinds.contains(&BindingProjectionKind::TargetConstructorOwnerType) {
        Some(BindingProjectionKind::TargetConstructorOwnerType)
    } else if kinds.contains(&BindingProjectionKind::TargetDeclaredValueType) {
        Some(BindingProjectionKind::TargetDeclaredValueType)
    } else if kinds.contains(&BindingProjectionKind::TargetTypeIdentity) {
        Some(BindingProjectionKind::TargetTypeIdentity)
    } else if kinds.contains(&BindingProjectionKind::TargetTypeOrDeclaredValueType) {
        Some(BindingProjectionKind::TargetTypeOrDeclaredValueType)
    } else {
        None
    };
    let kind = if matches!(
        selected,
        Some(
            BindingProjectionKind::TargetTypeIdentity
                | BindingProjectionKind::TargetConstructorOwnerType
        )
    ) {
        TypeLookupTargetKind::TypeReference
    } else {
        TypeLookupTargetKind::ValueExpression
    };
    (kind, selected, kinds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "d6fe0c806939: cancelled type lookup was reported as absence instead of a cancelled terminal status"
    )]
    fn cancelled_finish_preserves_terminal_status_without_type_targets() {
        let site = ResolvedReferenceSite {
            path: "Budget.cs".to_string(),
            text: "product".to_string(),
            range: crate::analyzer::Range {
                start_byte: 0,
                end_byte: "product".len(),
                start_line: 0,
                end_line: 0,
            },
            focus_start_byte: 0,
            focus_end_byte: "product".len(),
        };
        let outcome = finish_bounded_resolution(
            Some(BoundedResolution::Cancelled {
                work: Default::default(),
            }),
            Language::CSharp,
            site,
        );
        assert_eq!(outcome.status, TypeLookupStatus::Cancelled);
        assert_eq!(outcome.status.as_str(), "cancelled");
        assert!(outcome.types.is_empty(), "{outcome:#?}");
        assert_eq!(
            outcome.reference.as_ref().map(|site| site.text.as_str()),
            Some("product")
        );
        assert_eq!(outcome.diagnostics[0].kind, "cancelled");
    }
}
