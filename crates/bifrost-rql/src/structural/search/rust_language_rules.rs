use crate::analyzer::usages::get_definition::{
    DefinitionLookupOutcome, DefinitionLookupRequest, DefinitionLookupStatus,
    parse_tree_for_language, resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::query::RustRule;
use brokk_bifrost_analysis::analyzer::WorkspaceAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::{
    SelectedBindingUnavailable, SelectedTupleBinding,
};
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::WorkspaceSemanticOracle;
use brokk_bifrost_analysis::analyzer::semantic::{SemanticArtifact, SemanticRequest};
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_rust_analysis::analyzer::rust::{RustPatternName, rust_pattern_name_bounded};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use super::language_rules::{LanguageRuleMatches, UndecidedSite};
use super::semantic::{ArtifactUnavailable, SemanticQueryContext};

const QUERY: &str = "poem.web.query.Query";
const PATH: &str = "poem.web.path.Path";

pub(super) fn matches_for_file(
    analyzer: &dyn IAnalyzer,
    mut semantic: Option<&mut SemanticQueryContext<'_>>,
    cancellation: Option<&crate::cancellation::CancellationToken>,
    file: &ProjectFile,
    source: &str,
    rule: RustRule,
) -> LanguageRuleMatches {
    let Some(tree) = parse_tree_for_language(file, Language::Rust, source) else {
        return LanguageRuleMatches::incomplete(
            Vec::<Range>::new(),
            Language::Rust.config_label(),
            format!(
                "Rust syntax unavailable for {}",
                super::rel_path_string(file)
            ),
        );
    };
    let root = tree.root_node();
    // Find the tuple-struct patterns before any semantic work.
    let mut patterns = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            return LanguageRuleMatches::incomplete(
                Vec::<Range>::new(),
                Language::Rust.config_label(),
                "Rust pattern scan was cancelled".to_owned(),
            );
        }
        // Every tuple-struct pattern is collected, nested ones too, and each is
        // classified on its own: an outer `Some(..)` must not hide the
        // extractor written inside it.
        if node.kind() == "tuple_struct_pattern" {
            patterns.push(node);
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    // Resolve every constructor with the definition lookup, from the final
    // segment of its path (the `name` field of a scoped path), so a raw
    // identifier, a local struct, an enum variant and a prelude constructor
    // are all read structurally.
    let source_snapshot = Arc::<str>::from(source);
    let kinds = classify_constructors(analyzer, file, &source_snapshot, &patterns);
    // Only a pattern that is not definitely some other constructor can be a
    // Poem extractor, so only those need the selected admission. A file whose
    // patterns all resolve elsewhere (`Some`, `Ok`, local structs) never
    // materializes semantics.
    let wanted = patterns
        .iter()
        .zip(&kinds)
        .filter(|(_, kind)| !matches!(kind, Constructor::NotPoem))
        .map(|(node, _)| (node.start_byte(), node.end_byte()))
        .collect::<HashSet<_>>();
    let mut ranges = Vec::new();
    let mut undecided = Vec::new();
    let selected = if !wanted.is_empty() {
        match semantic
            .as_deref_mut()
            .map(|semantic| selected_binders(semantic, file, &wanted))
        {
            Some(Ok(binders)) => Some(binders),
            Some(Err(cause)) => {
                return LanguageRuleMatches::incomplete(
                    Vec::<Range>::new(),
                    Language::Rust.config_label(),
                    format!("selected Poem binder admission unavailable: {cause}"),
                );
            }
            None => None,
        }
    } else {
        None
    };
    for (node, kind) in patterns.into_iter().zip(kinds) {
        if cancellation.is_some_and(|token| token.is_cancelled()) {
            return LanguageRuleMatches::incomplete(
                Vec::<Range>::new(),
                Language::Rust.config_label(),
                "Rust pattern scan was cancelled".to_owned(),
            );
        }
        {
            let Some(constructor) = node.child_by_field_name("type") else {
                undecided.push(UndecidedSite::at(
                    node_range(node),
                    "tuple-struct constructor is missing",
                ));
                continue;
            };
            if let Some(reason) = selected
                .as_ref()
                .and_then(|binders| binders.unavailable_within(node.start_byte(), node.end_byte()))
            {
                // This candidate hit a limit; the other patterns in the file
                // keep their own decisions.
                undecided.push(UndecidedSite::at(node_range(constructor), reason));
                continue;
            }
            let has_selected = selected
                .as_ref()
                .is_some_and(|binders| binders.admits_within(node.start_byte(), node.end_byte()));
            if !has_selected {
                match kind {
                    Constructor::NotPoem => continue,
                    Constructor::Unresolved(reason) => {
                        undecided.push(UndecidedSite::at(node_range(constructor), reason));
                        continue;
                    }
                    Constructor::Poem => {}
                }
            }
            let mut cursor = node.walk();
            for field in node.named_children(&mut cursor) {
                if field.id() == constructor.id() {
                    continue;
                }
                match field.kind() {
                    "identifier" => {
                        if let Some(selected) = selected.as_ref().and_then(|binders| {
                            binders.decision(field.start_byte(), field.end_byte())
                        }) {
                            match selected {
                                SelectedBinder::Admitted => ranges.push(node_range(field)),
                                SelectedBinder::Rejected(reason)
                                | SelectedBinder::Unavailable(reason) => {
                                    undecided.push(UndecidedSite::at(node_range(field), reason))
                                }
                            }
                            continue;
                        }
                        if semantic.is_some() {
                            undecided.push(UndecidedSite::at(
                                node_range(field),
                                "selected Poem field admission missing",
                            ));
                            continue;
                        }
                        let mode =
                            rust_pattern_name_bounded(
                                root,
                                source,
                                field,
                                &mut |_| Ok::<_, ()>(()),
                            );
                        match mode {
                            Ok(RustPatternName::Binding) => ranges.push(node_range(field)),
                            Ok(RustPatternName::Unknown) | Err(()) => undecided.push(
                                UndecidedSite::at(node_range(field), "field binder is unresolved"),
                            ),
                            Ok(RustPatternName::ValueItem) => {}
                        }
                    }
                    "mut_pattern" | "ref_pattern" | "captured_pattern" => {
                        let mut children = field.walk();
                        for binder in field.named_children(&mut children) {
                            if binder.kind() != "identifier" {
                                continue;
                            }
                            // A wrapped binder takes the same selected decision
                            // as a bare one: `ref x` is rejected as by-reference
                            // and `mut x` outside a formal is rejected, so
                            // neither becomes a positive source on syntax alone.
                            match wrapped_binder_decision(
                                selected.as_ref(),
                                binder.start_byte(),
                                binder.end_byte(),
                            ) {
                                WrappedBinder::Match => ranges.push(node_range(binder)),
                                WrappedBinder::Undecided(reason) => {
                                    undecided.push(UndecidedSite::at(node_range(binder), reason))
                                }
                            }
                        }
                    }
                    "_" => {}
                    _ => undecided.push(UndecidedSite::at(
                        node_range(field),
                        "nested Poem field pattern needs a value projection",
                    )),
                }
            }
        }
    }
    LanguageRuleMatches::decided(
        ranges,
        undecided,
        Language::Rust.config_label(),
        rule.label(),
        file,
    )
}

/// What the definition lookup says a written constructor is.
enum Constructor {
    /// Definitely another constructor: a local struct or enum variant, or a
    /// prelude item such as `Some`, `Ok` and `Err`.
    NotPoem,
    /// Resolved to a Poem extractor's own declaration.
    Poem,
    /// Not decided by the lookup; the selected admission decides, or the site
    /// stays undecided with this reason.
    Unresolved(&'static str),
}

/// How a pattern's written constructor is looked up.
enum Probe<'t> {
    /// No written constructor node.
    Missing,
    /// A bare constructor, looked up as written.
    Bare(Node<'t>),
    /// A qualified constructor. It is not looked up by its last segment, which
    /// can resolve through an unrelated `use` of the same name (`use
    /// other::Query;` beside a written `poem::web::Query(..)`). Its first
    /// segment is looked up instead, to find out whether it names a local type
    /// or a prelude item; a first segment that cannot be looked up
    /// (`crate`, `self`, `super`) or that names a local module leaves the whole
    /// written path to be resolved.
    Qualified {
        first: Option<Node<'t>>,
        rooted_locally: bool,
        /// The path's last token. The lookup resolves the qualified path that
        /// a position inside one of its tokens belongs to.
        leaf: Node<'t>,
    },
}

fn constructor_probe<'t>(pattern: Node<'t>) -> Probe<'t> {
    let Some(constructor) = pattern.child_by_field_name("type") else {
        return Probe::Missing;
    };
    if constructor.kind() != "scoped_identifier" {
        return Probe::Bare(constructor);
    }
    let mut first = constructor;
    while first.kind() == "scoped_identifier" {
        match first.child_by_field_name("path") {
            Some(path) => first = path,
            // A leading `::` has no path node: a global path.
            None => {
                return Probe::Qualified {
                    first: None,
                    rooted_locally: false,
                    leaf: constructor
                        .child_by_field_name("name")
                        .unwrap_or(constructor),
                };
            }
        }
    }
    Probe::Qualified {
        first: matches!(first.kind(), "identifier" | "type_identifier").then_some(first),
        rooted_locally: matches!(first.kind(), "crate" | "self" | "super"),
        leaf: constructor
            .child_by_field_name("name")
            .unwrap_or(constructor),
    }
}

/// What the first lookup decided, or the written path it leaves to resolve.
enum FirstPass<'t> {
    Decided(Constructor),
    FullPath(Node<'t>),
}

fn definition_request(file: &ProjectFile, node: Node<'_>) -> DefinitionLookupRequest {
    DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(node.start_byte()),
        end_byte: Some(node.end_byte()),
    }
}

/// A request for the whole qualified path whose last token is `leaf`: a
/// position inside the token, with no end, names the path it belongs to.
fn path_request(file: &ProjectFile, leaf: Node<'_>) -> DefinitionLookupRequest {
    DefinitionLookupRequest {
        file: file.clone(),
        line: None,
        column: None,
        start_byte: Some(leaf.start_byte()),
        end_byte: None,
    }
}

/// Classify each pattern's constructor with batched definition lookups: one
/// for bare constructors and first segments, and one for the whole written
/// path of the qualified constructors that start locally.
fn classify_constructors(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &Arc<str>,
    patterns: &[Node<'_>],
) -> Vec<Constructor> {
    let lookup = |requests: Vec<DefinitionLookupRequest>| {
        if requests.is_empty() {
            return Vec::new();
        }
        resolve_definition_batch_with_source(analyzer, requests, file.clone(), Arc::clone(source))
    };
    let probes = patterns
        .iter()
        .map(|pattern| constructor_probe(*pattern))
        .collect::<Vec<_>>();
    let answers = lookup(
        probes
            .iter()
            .filter_map(|probe| match probe {
                Probe::Missing => None,
                Probe::Bare(node) => Some(definition_request(file, *node)),
                Probe::Qualified { first, .. } => {
                    first.map(|first| definition_request(file, first))
                }
            })
            .collect(),
    );
    let mut answers = answers.iter();
    let first_pass = probes
        .iter()
        .map(|probe| match probe {
            Probe::Missing => {
                FirstPass::Decided(Constructor::Unresolved("constructor identity unresolved"))
            }
            Probe::Bare(_) => FirstPass::Decided(match answers.next() {
                Some(answer) => classify_bare(answer),
                None => Constructor::Unresolved("constructor lookup unavailable"),
            }),
            Probe::Qualified {
                first,
                rooted_locally,
                leaf,
            } => {
                let answer = first.and_then(|_| answers.next());
                match (answer, *rooted_locally) {
                    (Some(answer), _) => classify_first_segment(answer, *leaf),
                    (None, true) => FirstPass::FullPath(*leaf),
                    (None, false) => FirstPass::Decided(Constructor::Unresolved(
                        "constructor identity unresolved",
                    )),
                }
            }
        })
        .collect::<Vec<_>>();
    let full_answers = lookup(
        first_pass
            .iter()
            .filter_map(|pass| match pass {
                FirstPass::FullPath(leaf) => Some(path_request(file, *leaf)),
                FirstPass::Decided(_) => None,
            })
            .collect(),
    );
    let mut full_answers = full_answers.iter();
    first_pass
        .into_iter()
        .map(|pass| match pass {
            FirstPass::Decided(constructor) => constructor,
            FirstPass::FullPath(_) => match full_answers.next() {
                Some(answer) => classify_full_path(answer),
                None => Constructor::Unresolved("constructor lookup unavailable"),
            },
        })
        .collect()
}

fn is_prelude_item(answer: &DefinitionLookupOutcome) -> bool {
    answer
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == "rust_prelude_item")
}

fn single_definition(answer: &DefinitionLookupOutcome) -> Option<&CodeUnit> {
    (answer.status == DefinitionLookupStatus::Resolved && answer.definitions.len() == 1)
        .then(|| &answer.definitions[0])
}

fn is_poem_extractor(definition: &CodeUnit) -> bool {
    let canonical = definition.fq_name().replace("::", ".");
    canonical == QUERY || canonical == PATH
}

/// A bare constructor: a prelude item or a local declaration is another
/// constructor; Poem's own declaration is Poem.
fn classify_bare(answer: &DefinitionLookupOutcome) -> Constructor {
    if is_prelude_item(answer) {
        return Constructor::NotPoem;
    }
    match single_definition(answer) {
        Some(definition) if is_poem_extractor(definition) => Constructor::Poem,
        Some(_) => Constructor::NotPoem,
        None => Constructor::Unresolved("constructor identity unresolved"),
    }
}

/// The first segment of a qualified constructor. A prelude item or a local
/// type before the last segment (`E::V`) makes the path a variant or associated
/// item. A local module could still re-export an extractor, so the whole path
/// is resolved. Anything else leaves the path to the selected admission.
fn classify_first_segment<'t>(answer: &DefinitionLookupOutcome, full: Node<'t>) -> FirstPass<'t> {
    if is_prelude_item(answer) {
        return FirstPass::Decided(Constructor::NotPoem);
    }
    match single_definition(answer) {
        Some(definition) if definition.is_module() => FirstPass::FullPath(full),
        Some(_) => FirstPass::Decided(Constructor::NotPoem),
        None => FirstPass::Decided(Constructor::Unresolved("constructor identity unresolved")),
    }
}

/// The whole written path of a constructor that starts locally. A local
/// declaration (variant or struct) is another constructor, Poem's declaration
/// is Poem, and a path that does not resolve stays undecided.
fn classify_full_path(answer: &DefinitionLookupOutcome) -> Constructor {
    match single_definition(answer) {
        Some(definition) if definition.is_module() => {
            Constructor::Unresolved("constructor identity unresolved")
        }
        Some(definition) if is_poem_extractor(definition) => Constructor::Poem,
        Some(_) => Constructor::NotPoem,
        None => Constructor::Unresolved("constructor identity unresolved"),
    }
}

/// What a binder inside `mut`, `ref` or `@` contributes to the match.
enum WrappedBinder {
    Match,
    Undecided(&'static str),
}

/// A wrapped binder takes the same selected decision as a bare one: `ref x` is
/// rejected as by-reference and a `mut x` outside a formal is rejected, so
/// neither becomes a source on syntax alone. Without a workspace there is no
/// selected decision and the syntactic rule applies.
fn wrapped_binder_decision(
    selected: Option<&SelectedBinders>,
    start: usize,
    end: usize,
) -> WrappedBinder {
    match selected.map(|binders| binders.decision(start, end)) {
        Some(Some(SelectedBinder::Admitted)) | None => WrappedBinder::Match,
        Some(Some(SelectedBinder::Rejected(reason) | SelectedBinder::Unavailable(reason))) => {
            WrappedBinder::Undecided(reason)
        }
        Some(None) => WrappedBinder::Undecided("selected Poem field admission missing"),
    }
}

enum SelectedBinder {
    Admitted,
    Rejected(&'static str),
    /// Admission of this one candidate hit a limit, named by the reason.
    Unavailable(&'static str),
}

/// Why the selected admission for a file could not be read. The cause is kept
/// so the incomplete reason says whether the run was interrupted, ran out of
/// budget, or failed.
enum SelectedBinderError {
    Interrupted(&'static str),
    Unavailable(&'static str),
    Provider(String),
}

impl std::fmt::Display for SelectedBinderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted(cause) => write!(formatter, "interrupted: {cause}"),
            Self::Unavailable(cause) => formatter.write_str(cause),
            Self::Provider(cause) => write!(formatter, "semantic provider failed: {cause}"),
        }
    }
}

/// Selected decisions keyed by binder span, with the admitted spans sorted so a
/// pattern finds its admitted binders without scanning every decision.
struct SelectedBinders {
    decisions: HashMap<(usize, usize), SelectedBinder>,
    admitted: Vec<(usize, usize)>,
    unavailable: Vec<((usize, usize), &'static str)>,
}

impl SelectedBinders {
    fn decision(&self, start: usize, end: usize) -> Option<&SelectedBinder> {
        self.decisions.get(&(start, end))
    }

    /// The limit that stopped a binder inside `start..end`, if one did.
    fn unavailable_within(&self, start: usize, end: usize) -> Option<&'static str> {
        let first = self
            .unavailable
            .partition_point(|((binder_start, _), _)| *binder_start < start);
        self.unavailable[first..]
            .iter()
            .take_while(|((binder_start, _), _)| *binder_start < end)
            .find(|((_, binder_end), _)| *binder_end <= end)
            .map(|(_, reason)| *reason)
    }

    /// Whether an admitted binder lies inside `start..end`.
    fn admits_within(&self, start: usize, end: usize) -> bool {
        let first = self
            .admitted
            .partition_point(|(binder_start, _)| *binder_start < start);
        self.admitted[first..]
            .iter()
            .take_while(|(binder_start, _)| *binder_start < end)
            .any(|(_, binder_end)| *binder_end <= end)
    }
}

/// Bind the syntax range to the one receipt-backed selected admission record.
/// The model, source, and import reads performed here enter the enclosing RQL
/// ledger, including rejected admissions. The file's artifact comes from the
/// query's own semantic context, so it is materialized at most once per query
/// and its cost is charged to the query's semantic budget; an exhausted budget
/// leaves the file's sites undecided.
fn selected_binders(
    semantic: &mut SemanticQueryContext<'_>,
    file: &ProjectFile,
    wanted_patterns: &HashSet<(usize, usize)>,
) -> Result<SelectedBinders, SelectedBinderError> {
    match semantic.with_cached_artifact(file, |workspace, snapshot, artifact, request| {
        admit_wanted_patterns(workspace, snapshot, artifact, request, wanted_patterns)
    }) {
        Ok(binders) => binders,
        Err(ArtifactUnavailable::BudgetExhausted) => Err(SelectedBinderError::Interrupted(
            "semantic budget exhausted",
        )),
        Err(ArtifactUnavailable::Unavailable) => Err(SelectedBinderError::Unavailable(
            "program semantics unavailable",
        )),
    }
}

fn admit_wanted_patterns(
    workspace: &WorkspaceAnalyzer,
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    artifact: &Arc<SemanticArtifact>,
    request: &mut SemanticRequest<'_>,
    wanted_patterns: &HashSet<(usize, usize)>,
) -> Result<SelectedBinders, SelectedBinderError> {
    let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
        workspace,
        snapshot,
        brokk_bifrost_analysis::analyzer::semantic::DispatchHints::empty(),
    );
    let mut decisions = HashMap::new();
    for procedure in artifact.procedures() {
        let handle = artifact
            .procedure_handle(procedure.id())
            .ok_or(SelectedBinderError::Unavailable("procedure handle missing"))?;
        // One traversal of the procedure's candidates admits every wanted one,
        // each on its own: a candidate that hits a limit marks only itself.
        let selected = oracle
            .selected_pattern_projections_where(&handle, request, |candidate| {
                procedure
                    .source_mapping(candidate.pattern_source)
                    .is_some_and(|mapping| {
                        let span = mapping.locator.anchor().span();
                        wanted_patterns
                            .contains(&(span.start_byte() as usize, span.end_byte() as usize))
                    })
            })
            .map_err(|error| SelectedBinderError::Provider(error.to_string()))?
            .ok_or(SelectedBinderError::Interrupted("cancelled"))?;
        for projection in selected.iter() {
            let mapping = procedure
                .source_mapping(projection.candidate.binder_source)
                .ok_or(SelectedBinderError::Unavailable("binder mapping missing"))?;
            let span = mapping.locator.anchor().span();
            let range = (span.start_byte() as usize, span.end_byte() as usize);
            let decision = match &projection.binding {
                SelectedTupleBinding::Admitted(binding)
                    if matches!(
                        binding.reads.selected_constructor.as_deref(),
                        Some(QUERY | PATH)
                    ) =>
                {
                    SelectedBinder::Admitted
                }
                SelectedTupleBinding::Admitted(_) => continue,
                SelectedTupleBinding::Rejected { reason, .. } => SelectedBinder::Rejected(reason),
                SelectedTupleBinding::Unavailable(SelectedBindingUnavailable::Cancelled) => {
                    return Err(SelectedBinderError::Interrupted("cancelled"));
                }
                SelectedTupleBinding::Unavailable(cause) => {
                    SelectedBinder::Unavailable(cause.reason())
                }
            };
            decisions.insert(range, decision);
        }
    }
    let mut admitted = Vec::new();
    let mut unavailable = Vec::new();
    for (range, decision) in &decisions {
        match decision {
            SelectedBinder::Admitted => admitted.push(*range),
            SelectedBinder::Unavailable(reason) => unavailable.push((*range, *reason)),
            SelectedBinder::Rejected(_) => {}
        }
    }
    admitted.sort_unstable();
    unavailable.sort_unstable();
    Ok(SelectedBinders {
        decisions,
        admitted,
        unavailable,
    })
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row.saturating_add(1),
        end_line: node.end_position().row.saturating_add(1),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::inline_project::InlineTestProject;
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;

    use crate::structural::CodeQuerySemanticLimits;
    use brokk_bifrost_analysis::analyzer::semantic::SemanticBudget;

    /// Run the rule under a fresh query context over `workspace`.
    fn rule_matches(
        workspace: &WorkspaceAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> super::LanguageRuleMatches {
        let mut semantic =
            SemanticQueryContext::new(workspace, None, CodeQuerySemanticLimits::default());
        matches_for_file(
            workspace.analyzer(),
            Some(&mut semantic),
            None,
            file,
            source,
            RustRule::PoemHandlerParam,
        )
    }

    #[test]
    fn admitted_binders_are_found_by_span_without_a_scan() {
        let mut decisions = HashMap::new();
        let admitted = [(10, 12), (30, 33), (50, 52)];
        for range in admitted {
            decisions.insert(range, SelectedBinder::Admitted);
        }
        decisions.insert((20, 22), SelectedBinder::Rejected("binder is by reference"));
        let binders = SelectedBinders {
            decisions,
            admitted: admitted.to_vec(),
            unavailable: Vec::new(),
        };
        assert!(binders.admits_within(5, 15));
        assert!(binders.admits_within(30, 33));
        assert!(binders.admits_within(0, 100));
        // A rejected binder inside the pattern does not count.
        assert!(!binders.admits_within(18, 25));
        // A binder that straddles the pattern's end is not inside it.
        assert!(!binders.admits_within(11, 32));
        assert!(!binders.admits_within(60, 90));
        assert!(matches!(
            binders.decision(20, 22),
            Some(SelectedBinder::Rejected("binder is by reference"))
        ));
        assert!(binders.decision(21, 22).is_none());
    }

    #[test]
    fn selected_binder_errors_keep_their_cause() {
        assert_eq!(
            SelectedBinderError::Interrupted("semantic budget exhausted").to_string(),
            "interrupted: semantic budget exhausted"
        );
        assert_eq!(
            SelectedBinderError::Provider("source access refused".to_owned()).to_string(),
            "semantic provider failed: source access refused"
        );
        assert_eq!(
            SelectedBinderError::Unavailable("program semantics unavailable").to_string(),
            "program semantics unavailable"
        );
    }

    #[test]
    fn wrapped_binders_take_the_selected_decision() {
        let binders = SelectedBinders {
            decisions: HashMap::from([
                ((10, 11), SelectedBinder::Admitted),
                ((20, 21), SelectedBinder::Rejected("binder is by reference")),
            ]),
            admitted: vec![(10, 11)],
            unavailable: Vec::new(),
        };
        assert!(matches!(
            wrapped_binder_decision(Some(&binders), 10, 11),
            WrappedBinder::Match
        ));
        assert!(matches!(
            wrapped_binder_decision(Some(&binders), 20, 21),
            WrappedBinder::Undecided("binder is by reference")
        ));
        // A binder the selected hook never decided is not a syntactic source.
        assert!(matches!(
            wrapped_binder_decision(Some(&binders), 30, 31),
            WrappedBinder::Undecided("selected Poem field admission missing")
        ));
        // Without a workspace there is no selected decision to consult.
        assert!(matches!(
            wrapped_binder_decision(None, 30, 31),
            WrappedBinder::Match
        ));
    }

    fn activate_poem_pack(
        workspace: &WorkspaceAnalyzer,
    ) -> std::sync::Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot> {
        use crate::analyzer::semantic_model::{
            CatalogOptions, CompilerOptions, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
            SemanticModelRuntimeOutcome, SemanticPackCatalog, SessionPackSource,
            SessionPackSourceKind, SourceFormat, acquire_active_semantic_models, compile_source,
        };
        let pack = compile_source(
            SourceFormat::Json,
            include_str!("tests/fixtures/rust-poem-g3-test-only.json").as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap_or_else(|diagnostics| panic!("Poem test pack compiles: {diagnostics:#?}"));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default())
            .expect("ephemeral semantic-pack catalog");
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test:poem-oversized-formal".to_owned(),
                },
            )
            .expect("register Poem test pack");
        let activation = acquire_active_semantic_models(
            workspace.analyzer(),
            &catalog,
            None,
            &SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("version"),
                evidence: vec![SemanticModelActivationEvidence {
                    language: "rust".to_owned(),
                    ecosystem: "cargo".to_owned(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                }],
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            },
            &crate::cancellation::CancellationToken::default(),
        );
        match activation {
            SemanticModelRuntimeOutcome::Ready { snapshot, .. } => snapshot,
            other => panic!("Poem test pack activates: {other:#?}"),
        }
    }

    #[test]
    fn an_oversized_poem_formal_marks_only_itself_incomplete() {
        // The second formal's type exceeds the admission alias budget, so its own
        // admission is unavailable. The valid handler before it must still match.
        let depth = 300;
        let huge = format!("{}u8{}", "W<".repeat(depth), ">".repeat(depth));
        let source = format!(
            "use poem::web::Query;\npub struct W<T>(pub T);\n\
             pub fn good(Query(f): Query<String>) {{ let _ = f; }}\n\
             pub fn huge(Query(g): Query<{huge}>) {{ let _ = g; }}\n"
        );
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let snapshot = activate_poem_pack(&workspace);
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot),
        );
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let matched = rule_matches(&workspace, &file, &source);
        let spans = matched
            .matches
            .iter()
            .map(|matched| &source[matched.select.start_byte..matched.select.end_byte])
            .collect::<Vec<_>>();
        assert_eq!(spans, ["f"], "{:?}", matched.diagnostics);
        let [diagnostic] = matched.diagnostics.as_slice() else {
            panic!("one incomplete diagnostic: {:?}", matched.diagnostics);
        };
        let message = format!("{diagnostic:?}");
        assert!(
            message.contains("formal type exceeds the alias budget"),
            "the incomplete site names its limit, not an interruption: {message}"
        );
        // Only the oversized site is undecided.
        assert_eq!(message.matches("bytes").count(), 1, "{message}");
    }

    #[test]
    fn a_limit_marks_the_stopped_binder_with_its_named_cause() {
        let binders = SelectedBinders {
            decisions: HashMap::from([
                ((10, 11), SelectedBinder::Admitted),
                (
                    (40, 41),
                    SelectedBinder::Unavailable("formal type exceeds the alias budget"),
                ),
            ]),
            admitted: vec![(10, 11)],
            unavailable: vec![((40, 41), "formal type exceeds the alias budget")],
        };
        assert_eq!(
            binders.unavailable_within(30, 50),
            Some("formal type exceeds the alias budget")
        );
        assert_eq!(binders.unavailable_within(0, 20), None);
        assert!(
            binders.admits_within(0, 20),
            "the other binder is still admitted"
        );
        assert!(matches!(
            wrapped_binder_decision(Some(&binders), 40, 41),
            WrappedBinder::Undecided("formal type exceeds the alias budget")
        ));
    }

    /// The reads `matches_for_file` performs on `source` without and with a
    /// workspace. They differ exactly when the selected admission ran, because
    /// only it materializes program semantics; definition lookup reads both.
    fn poem_rule_reads(source: &str) -> ([u8; 32], [u8; 32]) {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let reads = |with_workspace: bool| {
            // The context reads the active model set when it is built; only
            // what the rule itself reads is compared.
            let mut semantic = with_workspace.then(|| {
                SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default())
            });
            let (_, receipt) = QueryReadReceipt::capture(workspace.analyzer(), || {
                matches_for_file(
                    workspace.analyzer(),
                    semantic.as_mut(),
                    None,
                    &file,
                    source,
                    RustRule::PoemHandlerParam,
                )
            });
            *receipt.digest().as_bytes()
        };
        (reads(false), reads(true))
    }

    #[test]
    fn only_a_possible_poem_extractor_triggers_semantic_reads() {
        // Constructors that resolve definitely elsewhere decide the file from
        // syntax and lookup alone: prelude `Some`/`Ok`/`Err`, a local struct and
        // a local enum variant.
        let (without, reads) = poem_rule_reads(
            "struct Local(u8);\nenum E { V(u8) }\n\
             pub fn f(a: Option<u8>, b: Result<u8, u8>, c: Local, d: E) {\n\
             if let Some(x) = a {} if let Err(v) = b {} let Local(z) = c; if let E::V(w) = d {}\n\
             if let Some(Ok(n)) = Some(b) {}\n}\n",
        );
        assert_eq!(reads, without, "no pattern here can be a Poem extractor");

        // Everything else is admitted: a written Query, a raw identifier, a
        // renamed import, and a re-export from another module.
        for source in [
            "use poem::web::Query;\npub fn h(Query(f): Query<String>) { let _ = f; }\n",
            "use poem::web::Query;\npub fn h(r#Query(f): Query<String>) { let _ = f; }\n",
            "use poem::web::Query as Q;\npub fn h(Q(f): Q<String>) { let _ = f; }\n",
            "mod web { pub use poem::web::Query as PoemQuery; }\nuse crate::web::PoemQuery;\n\
             pub fn h(PoemQuery(f): PoemQuery<String>) { let _ = f; }\n",
        ] {
            let (without, reads) = poem_rule_reads(source);
            assert_ne!(reads, without, "a possible extractor is admitted: {source}");
        }
    }

    #[test]
    fn a_locally_rooted_constructor_path_is_resolved_whole() {
        // `crate::`, `self::`, `super::` and a local module cannot be probed by
        // their first segment; the whole written path resolves to the local
        // variant or struct, which is not Poem.
        for source in [
            "pub enum Msg { Quit(u8) }\n\
             pub fn h(m: Msg) { match m { crate::Msg::Quit(x) => { let _ = x; } } }\n",
            "pub enum Msg { Quit(u8) }\n\
             pub fn h(m: Msg) { match m { self::Msg::Quit(x) => { let _ = x; } } }\n",
            "pub enum Msg { Quit(u8) }\nmod inner {\n\
             pub fn h(m: super::Msg) { match m { super::Msg::Quit(x) => { let _ = x; } } }\n}\n",
            "mod commands { pub enum Cmd { Run(u8) } }\n\
             pub fn h(c: commands::Cmd) { match c { commands::Cmd::Run(x) => { let _ = x; } } }\n",
            "mod commands { pub struct Run(pub u8); }\n\
             pub fn h(c: commands::Run) { let commands::Run(x) = c; let _ = x; }\n",
        ] {
            let (without, reads) = poem_rule_reads(source);
            assert_eq!(
                reads, without,
                "a local variant decides from syntax: {source}"
            );
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
                )
                .file("src/lib.rs", source)
                .build();
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .expect("Rust workspace");
            let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
            let matched = rule_matches(&workspace, &file, source);
            assert!(
                matched.matches.is_empty() && matched.diagnostics.is_empty(),
                "not Poem, and nothing undecided: {source} {:?}",
                matched.diagnostics
            );
        }

        // A path that cannot be resolved stays a candidate, and the written
        // Poem extractor is still admitted.
        for source in [
            "pub fn h(c: u8) { let crate::nowhere::Thing(x) = c; let _ = x; }\n",
            "pub fn h(poem::web::Query(f): poem::web::Query<String>) { let _ = f; }\n",
        ] {
            let (without, reads) = poem_rule_reads(source);
            assert_ne!(reads, without, "a possible extractor is admitted: {source}");
        }
    }

    #[test]
    fn an_extractor_nested_inside_another_pattern_is_never_silently_absent() {
        // `Some` is definitely not Poem, but the `Query` written inside it is a
        // possible extractor. It is not an admitted parameter position, so it
        // must read as undecided rather than disappear.
        let source = "use poem::web::Query;\n\
             pub fn h(opt: Option<Query<String>>) { if let Some(Query(x)) = opt { let _ = x; } }\n";
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", source)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let snapshot = activate_poem_pack(&workspace);
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot),
        );
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let matched = rule_matches(&workspace, &file, source);
        assert!(matched.matches.is_empty(), "{:?}", matched.matches);
        let [diagnostic] = matched.diagnostics.as_slice() else {
            panic!(
                "the nested extractor is undecided: {:?}",
                matched.diagnostics
            );
        };
        assert!(format!("{diagnostic:?}").contains("constructor identity unresolved"));
    }

    fn two_handler_workspace() -> (
        crate::structural::search::tests::inline_project::BuiltInlineTestProject,
        WorkspaceAnalyzer,
    ) {
        let cargo = "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n";
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", cargo)
            .file(
                "src/lib.rs",
                "pub mod other;\nuse poem::web::Query;\n\
                 pub fn a(Query(f): Query<String>) { let _ = f; }\n",
            )
            .file(
                "src/other.rs",
                "use poem::web::Query;\n\
                 pub fn b(Query(g): Query<String>) { let _ = g; }\n",
            )
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        (project, workspace)
    }

    #[test]
    fn a_file_is_materialized_once_per_query() {
        let (_project, workspace) = two_handler_workspace();
        let snapshot = activate_poem_pack(&workspace);
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot),
        );
        let root = workspace.analyzer().project().root().to_path_buf();
        let lib = ProjectFile::new(&root, "src/lib.rs");
        let other = ProjectFile::new(&root, "src/other.rs");
        let lib_source = "pub mod other;\nuse poem::web::Query;\n\
             pub fn a(Query(f): Query<String>) { let _ = f; }\n";
        let other_source = "use poem::web::Query;\n\
             pub fn b(Query(g): Query<String>) { let _ = g; }\n";
        let mut semantic =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        let mut run = |file: &ProjectFile, source: &str| {
            matches_for_file(
                workspace.analyzer(),
                Some(&mut semantic),
                None,
                file,
                source,
                RustRule::PoemHandlerParam,
            )
            .matches
            .len()
        };
        assert_eq!(run(&lib, lib_source), 1);
        assert_eq!(
            run(&lib, lib_source),
            1,
            "the second run reuses the artifact"
        );
        assert_eq!(run(&other, other_source), 1);
        assert_eq!(
            semantic.materialization_attempts(),
            2,
            "one materialization per file per query"
        );
    }

    #[test]
    fn a_tight_semantic_budget_leaves_the_second_file_undecided() {
        let (_project, workspace) = two_handler_workspace();
        let snapshot = activate_poem_pack(&workspace);
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot),
        );
        let limits = CodeQuerySemanticLimits {
            max_materialized_files: 1,
            ..CodeQuerySemanticLimits::default()
        };
        let root = workspace.analyzer().project().root().to_path_buf();
        let mut semantic = SemanticQueryContext::new(&workspace, None, limits);
        let mut run = |path: &str, source: &str| {
            matches_for_file(
                workspace.analyzer(),
                Some(&mut semantic),
                None,
                &ProjectFile::new(&root, path),
                source,
                RustRule::PoemHandlerParam,
            )
        };
        let first = run(
            "src/lib.rs",
            "pub mod other;\nuse poem::web::Query;\n\
             pub fn a(Query(f): Query<String>) { let _ = f; }\n",
        );
        assert_eq!(first.matches.len(), 1, "{:?}", first.diagnostics);
        let second = run(
            "src/other.rs",
            "use poem::web::Query;\n\
             pub fn b(Query(g): Query<String>) { let _ = g; }\n",
        );
        assert!(second.matches.is_empty(), "{:?}", second.matches);
        let [diagnostic] = second.diagnostics.as_slice() else {
            panic!("the file is undecided: {:?}", second.diagnostics);
        };
        assert!(
            format!("{diagnostic:?}").contains("semantic budget exhausted"),
            "{diagnostic:?}"
        );
        assert_eq!(
            semantic.materialization_attempts(),
            1,
            "nothing is materialized past the budget"
        );
        let reported = semantic.take_diagnostics();
        assert!(
            reported
                .iter()
                .any(|d| format!("{d:?}").contains("semantic/files")),
            "the query reports its own budget diagnostic: {reported:?}"
        );
    }

    #[test]
    fn a_qualified_poem_constructor_is_not_judged_by_an_unrelated_leaf() {
        // `use other::Query` makes the bare leaf `Query` resolve to a local
        // type, but the written `poem::web::Query` is a different path.
        for source in [
            "pub struct Query<T>(pub T);\n\
             pub fn h(poem::web::Query(f): poem::web::Query<String>) { let _ = f; }\n",
            "mod other { pub struct Query<T>(pub T); }\nuse other::Query;\n\
             pub fn h(poem::web::Query(f): poem::web::Query<String>) { let _ = f; }\n",
        ] {
            let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", source)
            .build();
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .expect("Rust workspace");
            let snapshot = activate_poem_pack(&workspace);
            let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
            let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
            let matched = rule_matches(&workspace, &file, source);
            let spans = matched
                .matches
                .iter()
                .map(|matched| &source[matched.select.start_byte..matched.select.end_byte])
                .collect::<Vec<_>>();
            assert!(
                spans == ["f"] || !matched.diagnostics.is_empty(),
                "admitted or undecided, never silently absent: {spans:?} {:?}",
                matched.diagnostics
            );
        }
    }

    #[test]
    fn a_file_over_the_syntax_limit_leaves_a_possible_extractor_undecided() {
        // Admission reads the file's syntax under a 1 MiB limit. Past it, a
        // possible extractor is undecided with the named limit, not clean.
        let code = "use poem::web::Query;\n\
             pub fn h(Query(f): Query<String>) { let _ = f; }\n";
        // Many short lines: a single 1 MiB line is refused earlier, by the
        // per-line source limit, before the syntax limit applies.
        let padding = format!("//{}\n", "x".repeat(990)).repeat(1_100);
        let source = format!("{padding}{code}");
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let snapshot = activate_poem_pack(&workspace);
        let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            Some(snapshot),
        );
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let matched = rule_matches(&workspace, &file, &source);
        assert!(matched.matches.is_empty(), "{:?}", matched.matches);
        let [diagnostic] = matched.diagnostics.as_slice() else {
            panic!("the extractor is undecided: {:?}", matched.diagnostics);
        };
        assert!(
            format!("{diagnostic:?}").contains("syntax size limit"),
            "{diagnostic:?}"
        );
    }

    #[test]
    fn a_raw_identifier_and_a_cross_module_re_export_keep_their_source() {
        // `r#Query` and a re-export renamed in another module are the same
        // extractor as `Query`; the prefilter must not drop them.
        for (constructor, uses) in [
            ("r#Query", "use poem::web::Query;"),
            (
                "PoemQuery",
                "mod web { pub use poem::web::Query as PoemQuery; }\nuse crate::web::PoemQuery;",
            ),
        ] {
            let source = format!(
                "{uses}\npub fn h({constructor}(f): {constructor}<String>) {{ let _ = f; }}\n"
            );
            let project = InlineTestProject::with_language(Language::Rust)
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
                )
                .file("src/lib.rs", &source)
                .build();
            let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
                project.project_dyn(),
                AnalyzerConfig::default(),
            )
            .expect("Rust workspace");
            let snapshot = activate_poem_pack(&workspace);
            let _scope = crate::analyzer::AnalyzerQueryScope::with_active_semantic_model_snapshot(
                workspace.analyzer(),
                Some(snapshot),
            );
            let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
            let matched = rule_matches(&workspace, &file, &source);
            let spans = matched
                .matches
                .iter()
                .map(|matched| &source[matched.select.start_byte..matched.select.end_byte])
                .collect::<Vec<_>>();
            assert_eq!(spans, ["f"], "{constructor}: {:?}", matched.diagnostics);
        }
    }

    #[test]
    fn selecting_wanted_candidates_visits_each_candidate_once() {
        let params = (0..12)
            .map(|index| format!("Query(p{index}): Query<String>"))
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!("use poem::web::Query;\npub fn h({params}) {{}}\n");
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n\n[dependencies]\npoem = \"3.1.7\"\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let outcome = workspace
            .materialize_program_semantics(&file, &mut request)
            .expect("materialization");
        let artifact = outcome.available_value().expect("artifact");
        let procedure = &artifact.procedures()[0];
        let handle = artifact.procedure_handle(procedure.id()).expect("handle");
        let candidates = procedure.guarded_pattern_projections().len();
        assert_eq!(candidates, 12);
        let oracle = WorkspaceSemanticOracle::new(&workspace);
        let mut visits = 0usize;
        let selected = oracle
            .selected_pattern_projections_where(&handle, &mut request, |_| {
                visits += 1;
                false
            })
            .expect("selection")
            .expect("not cancelled");
        assert!(selected.is_empty());
        assert_eq!(
            visits, candidates,
            "one visit per candidate, not per candidate pair"
        );
    }

    #[test]
    fn a_file_without_tuple_patterns_makes_no_semantic_reads() {
        let project = InlineTestProject::with_language(Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
            )
            .file(
                "src/lib.rs",
                "pub fn handler(name: String) -> usize { name.len() }\n",
            )
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            project.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("Rust workspace");
        let file = ProjectFile::new(workspace.analyzer().project().root(), "src/lib.rs");
        let source = "pub fn handler(name: String) -> usize { name.len() }\n";
        let (_, empty) = QueryReadReceipt::capture(workspace.analyzer(), || ());
        // The context reads the active model set when it is built; only what
        // the rule itself reads is compared.
        let mut semantic =
            SemanticQueryContext::new(&workspace, None, CodeQuerySemanticLimits::default());
        let (matches, receipt) = QueryReadReceipt::capture(workspace.analyzer(), || {
            matches_for_file(
                workspace.analyzer(),
                Some(&mut semantic),
                None,
                &file,
                source,
                RustRule::PoemHandlerParam,
            )
        });
        assert!(matches.matches.is_empty());
        assert!(matches.diagnostics.is_empty(), "{:?}", matches.diagnostics);
        assert_eq!(
            receipt.digest().as_bytes(),
            empty.digest().as_bytes(),
            "syntax alone decides a file with no tuple-struct pattern"
        );
    }
}
