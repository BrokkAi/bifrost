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
use brokk_bifrost_analysis::analyzer::semantic::type_flow::source_span_for_node;
use brokk_bifrost_analysis::analyzer::semantic::workspace_oracle::{
    SelectedPatternObservation, WorkspaceSemanticOracle,
};
use brokk_bifrost_analysis::analyzer::semantic::{SemanticArtifact, SemanticRequest, SourceSpan};
use brokk_bifrost_analysis::analyzer::semantic_model::ActiveSemanticModelSnapshot;
use brokk_bifrost_rust_analysis::analyzer::rust::{RustPatternName, rust_pattern_name_bounded};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use super::language_rules::{LanguageRuleMatch, LanguageRuleMatches, UndecidedSite};
use super::semantic::SemanticQueryContext;

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
        .flat_map(|(node, _)| {
            let constructor = node.child_by_field_name("type").map(|child| child.id());
            node.children(&mut node.walk())
                .filter(|child| {
                    (child.is_named() || child.kind() == "_")
                        && !child.is_extra()
                        && Some(child.id()) != constructor
                })
                .map(source_span_for_node)
                .collect::<Vec<_>>()
        })
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
            let has_selected = selected.as_ref().is_some_and(|binders| {
                binders.admits_within(node.start_byte(), node.end_byte())
                    && node.children(&mut node.walk()).any(|field| {
                        field.id() != constructor.id()
                            && matches!(
                                binders.decision(field.start_byte(), field.end_byte()),
                                Some(SelectedBinder::Admitted)
                            )
                    })
            });
            let unavailable = selected
                .as_ref()
                .and_then(|binders| binders.unavailable_within(node.start_byte(), node.end_byte()));
            if !has_selected {
                match kind {
                    Constructor::NotPoem => continue,
                    Constructor::Unresolved(reason) => {
                        // The definition lookup could not name this constructor,
                        // but the selected admission may still have hit a named
                        // limit for it. Report that limit rather than the
                        // prefilter's generic reason.
                        undecided.push(UndecidedSite::at(
                            node_range(constructor),
                            unavailable.unwrap_or(reason),
                        ));
                        continue;
                    }
                    Constructor::Poem => {}
                }
            }
            if let Some(reason) = unavailable {
                // This candidate hit a limit; the other patterns in the file
                // keep their own decisions.
                undecided.push(UndecidedSite::at(node_range(constructor), reason));
                continue;
            }
            let mut cursor = node.walk();
            for field in node
                .children(&mut cursor)
                .filter(|child| (child.is_named() || child.kind() == "_") && !child.is_extra())
            {
                if field.id() == constructor.id() {
                    continue;
                }
                if semantic.is_some() {
                    match selected
                        .as_ref()
                        .and_then(|binders| binders.decision(field.start_byte(), field.end_byte()))
                    {
                        Some(SelectedBinder::Admitted) => {
                            for admitted in
                                &selected.as_ref().expect("selected field").field_binders
                                    [&(field.start_byte(), field.end_byte())]
                            {
                                let (start, end) = (admitted.start, admitted.end);
                                let binder = root
                                    .descendant_for_byte_range(start, end)
                                    .expect("admitted binder belongs to selected AST");
                                assert_eq!((binder.start_byte(), binder.end_byte()), (start, end));
                                ranges.push(LanguageRuleMatch {
                                    selected_pattern_source:
                                        super::SelectedPatternSourceEvidence::Admitted(Arc::clone(
                                            &admitted.proof,
                                        )),
                                    select: node_range(binder),
                                    report: node_range(field),
                                    heuristic: None,
                                });
                            }
                        }
                        Some(
                            SelectedBinder::Rejected(reason) | SelectedBinder::Unavailable(reason),
                        ) => undecided.push(UndecidedSite::at(node_range(field), reason)),
                        None => undecided.push(UndecidedSite::at(
                            node_range(field),
                            "selected Poem field has no admitted value observation",
                        )),
                    }
                    continue;
                }
                match field.kind() {
                    "identifier" => {
                        let mode =
                            rust_pattern_name_bounded(
                                root,
                                source,
                                field,
                                &mut |_| Ok::<_, ()>(()),
                            );
                        match mode {
                            Ok(RustPatternName::Binding) => ranges.push(node_range(field).into()),
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
                                WrappedBinder::Match => ranges.push(node_range(binder).into()),
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
struct AdmittedFieldBinder {
    start: usize,
    end: usize,
    proof: Arc<SelectedPatternObservation>,
}

struct SelectedBinders {
    field_binders: HashMap<(usize, usize), Vec<AdmittedFieldBinder>>,
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
    wanted_patterns: &HashSet<SourceSpan>,
) -> Result<SelectedBinders, SelectedBinderError> {
    match semantic.with_cached_artifact(file, |workspace, snapshot, artifact, request| {
        admit_wanted_patterns(workspace, snapshot, artifact, request, wanted_patterns)
    }) {
        Ok(binders) => binders,
        Err(refusal) if refusal.is_budget_exhausted() => Err(SelectedBinderError::Interrupted(
            "semantic budget exhausted",
        )),
        Err(_) => Err(SelectedBinderError::Unavailable(
            "program semantics unavailable",
        )),
    }
}

// File-local containment index. The sorted leaves preserve the old admission
// order, including nested fields; each balanced subtree records its maximum
// end so unrelated prefixes are pruned rather than scanned backwards.
struct WantedFieldIndex {
    fields: Vec<SourceSpan>,
    max_end: Vec<u32>,
    leaf_count: usize,
}

impl WantedFieldIndex {
    fn new(
        fields: impl IntoIterator<Item = SourceSpan>,
        mut visit: impl FnMut() -> Result<(), SelectedBinderError>,
    ) -> Result<Self, SelectedBinderError> {
        let mut sorted = Vec::new();
        for field in fields {
            visit()?;
            sorted.push(field);
        }
        // Fallible bottom-up merge sort: even sorting observes request stops,
        // without an uninterruptible comparison callback or recursive walk.
        let mut scratch = Vec::with_capacity(sorted.len());
        let mut width = 1;
        while width < sorted.len() {
            scratch.clear();
            for lo in (0..sorted.len()).step_by(width.saturating_mul(2)) {
                let middle = (lo + width).min(sorted.len());
                let end = middle.saturating_add(width).min(sorted.len());
                let (mut left, mut right) = (lo, middle);
                while left < middle || right < end {
                    visit()?;
                    let next = if right == end || (left < middle && sorted[left] <= sorted[right]) {
                        let next = sorted[left];
                        left += 1;
                        next
                    } else {
                        let next = sorted[right];
                        right += 1;
                        next
                    };
                    scratch.push(next);
                }
            }
            std::mem::swap(&mut sorted, &mut scratch);
            width = width.saturating_mul(2);
        }
        let leaf_count = sorted.len().max(1).next_power_of_two();
        let mut max_end = Vec::with_capacity(2 * leaf_count);
        for _ in 0..2 * leaf_count {
            visit()?;
            max_end.push(0);
        }
        for (offset, field) in sorted.iter().enumerate() {
            visit()?;
            max_end[leaf_count + offset] = field.end_byte();
        }
        for node in (1..leaf_count).rev() {
            visit()?;
            max_end[node] = max_end[2 * node].max(max_end[2 * node + 1]);
        }
        Ok(Self {
            fields: sorted,
            max_end,
            leaf_count,
        })
    }

    fn containing(
        &self,
        binder: SourceSpan,
        mut visit: impl FnMut() -> Result<(), SelectedBinderError>,
    ) -> Result<Vec<SourceSpan>, SelectedBinderError> {
        let mut matches = Vec::new();
        let mut pending = vec![(1, 0, self.leaf_count)];
        while let Some((node, lo, hi)) = pending.pop() {
            visit()?;
            if lo >= self.fields.len()
                || self.fields[lo].start_byte() > binder.start_byte()
                || self.max_end[node] < binder.end_byte()
            {
                continue;
            }
            if hi - lo == 1 {
                matches.push(self.fields[lo]);
            } else {
                let middle = lo + (hi - lo) / 2;
                pending.push((2 * node + 1, middle, hi));
                pending.push((2 * node, lo, middle));
            }
        }
        Ok(matches)
    }
}

fn visit_wanted_field_index(request: &mut SemanticRequest<'_>) -> Result<(), SelectedBinderError> {
    if request.cancellation.is_cancelled() {
        return Err(SelectedBinderError::Interrupted("cancelled"));
    }
    if !request.charge_execution_traversal(1) {
        return Err(SelectedBinderError::Interrupted(
            "semantic traversal budget exhausted",
        ));
    }
    request
        .budget
        .charge_work(brokk_bifrost_analysis::analyzer::semantic::SemanticWork {
            nested_entries: 1,
            ..Default::default()
        });
    Ok(())
}

fn admit_wanted_patterns(
    workspace: &WorkspaceAnalyzer,
    snapshot: Option<Arc<ActiveSemanticModelSnapshot>>,
    artifact: &Arc<SemanticArtifact>,
    request: &mut SemanticRequest<'_>,
    wanted_patterns: &HashSet<SourceSpan>,
) -> Result<SelectedBinders, SelectedBinderError> {
    let oracle = WorkspaceSemanticOracle::with_dispatch_hints(
        workspace,
        snapshot,
        brokk_bifrost_analysis::analyzer::semantic::DispatchHints::empty(),
    );
    let mut decisions = HashMap::new();
    let mut field_binders: HashMap<_, Vec<_>> = HashMap::new();
    let fields = WantedFieldIndex::new(wanted_patterns.iter().copied(), || {
        visit_wanted_field_index(request)
    })?;
    for procedure in artifact.procedures() {
        visit_wanted_field_index(request)?;
        let handle = artifact
            .procedure_handle(procedure.id())
            .ok_or(SelectedBinderError::Unavailable("procedure handle missing"))?;
        for candidate in procedure.guarded_pattern_projections() {
            visit_wanted_field_index(request)?;
            let Some(mapping) = procedure.source_mapping(candidate.binder_source) else {
                return Err(SelectedBinderError::Unavailable("binder mapping missing"));
            };
            let binder_span = mapping.locator.anchor().span();
            for field in fields.containing(binder_span, || visit_wanted_field_index(request))? {
                let projection = oracle
                    .selected_pattern_source_at(
                        &handle,
                        candidate.ordinal,
                        field.start_byte() as usize..field.end_byte() as usize,
                        request,
                    )
                    .map_err(|error| SelectedBinderError::Provider(error.to_string()))?
                    .ok_or(SelectedBinderError::Interrupted("cancelled"))?;
                let decision = match &projection.binding {
                    SelectedTupleBinding::Admitted(binding)
                        if matches!(
                            binding.reads.selected_constructor.as_deref(),
                            Some(QUERY | PATH)
                        ) =>
                    {
                        SelectedBinder::Admitted
                    }
                    SelectedTupleBinding::Observed(source)
                        if matches!(
                            source.binding.reads.selected_constructor.as_deref(),
                            Some(QUERY | PATH)
                        ) =>
                    {
                        SelectedBinder::Admitted
                    }
                    SelectedTupleBinding::Admitted(_) | SelectedTupleBinding::Observed(_) => {
                        continue;
                    }
                    SelectedTupleBinding::Rejected { reason, .. } => {
                        SelectedBinder::Rejected(reason)
                    }
                    SelectedTupleBinding::Unavailable(SelectedBindingUnavailable::Cancelled) => {
                        return Err(SelectedBinderError::Interrupted("cancelled"));
                    }
                    SelectedTupleBinding::Unavailable(cause) => {
                        SelectedBinder::Unavailable(cause.reason())
                    }
                };
                let range = (field.start_byte() as usize, field.end_byte() as usize);
                if matches!(decision, SelectedBinder::Admitted) {
                    let proof = Arc::new(
                        projection
                            .into_binding_observation()
                            .expect("canonical admitted field has a binding observation"),
                    );
                    proof.replay_reads(workspace);
                    field_binders
                        .entry(range)
                        .or_default()
                        .push(AdmittedFieldBinder {
                            start: binder_span.start_byte() as usize,
                            end: binder_span.end_byte() as usize,
                            proof,
                        });
                }
                // A field with several observable binders remains undecided if
                // any of those observations could not be admitted.
                match decisions.entry(range) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(decision);
                    }
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        if matches!(entry.get(), SelectedBinder::Admitted) {
                            entry.insert(decision);
                        }
                    }
                }
            }
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
        field_binders,
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

    fn index_test_span(start: u32, end: u32) -> SourceSpan {
        use brokk_bifrost_analysis::analyzer::semantic::SourcePosition;
        SourceSpan::new(
            SourcePosition::new(start, 0, start),
            SourcePosition::new(end, 0, end),
        )
        .expect("ordered single-line span")
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: every binder scanned every wanted field, including unrelated spans"
    )]
    fn wanted_field_index_prunes_unrelated_fields_and_preserves_nested_order() {
        for exponent in [8, 12] {
            let count = 1usize << exponent;
            let outer = index_test_span(0, (count * 10) as u32);
            let fields = std::iter::once(outer).chain(
                (1..count)
                    .rev()
                    .map(|i| index_test_span((i * 10) as u32, (i * 10 + 8) as u32)),
            );
            let mut build_visits = 0;
            let index = WantedFieldIndex::new(fields, || {
                build_visits += 1;
                Ok(())
            })
            .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(build_visits, (exponent + 5) * count - 1);
            let mut query_visits = 0;
            for i in 1..count {
                let binder = index_test_span((i * 10 + 2) as u32, (i * 10 + 4) as u32);
                let matches = index
                    .containing(binder, || {
                        query_visits += 1;
                        Ok(())
                    })
                    .unwrap_or_else(|error| panic!("{error}"));
                assert_eq!(
                    matches,
                    vec![outer, index_test_span((i * 10) as u32, (i * 10 + 8) as u32)]
                );
            }
            // Two containing leaves (one long-lived outer field) require at
            // most two root-to-leaf paths and their rejected siblings.
            assert!(query_visits <= (count - 1) * (4 * exponent + 1));
            assert!(build_visits + query_visits < count * (count - 1));
        }
        let fields = [
            index_test_span(2, 90),
            index_test_span(2, 60),
            index_test_span(8, 40),
        ];
        let index =
            WantedFieldIndex::new(fields, || Ok(())).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            index
                .containing(index_test_span(10, 12), || Ok(()))
                .unwrap_or_else(|error| panic!("{error}")),
            vec![fields[1], fields[0], fields[2]]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: skipped field candidates bypassed request cancellation and traversal limits"
    )]
    fn wanted_field_index_build_and_pruned_queries_observe_request_stops() {
        use brokk_bifrost_analysis::analyzer::semantic::SemanticExecutionBudget;
        let fields = (0..64)
            .map(|i| index_test_span(i * 10, i * 10 + 8))
            .collect::<Vec<_>>();
        let index = WantedFieldIndex::new(fields.iter().copied(), || Ok(()))
            .unwrap_or_else(|error| panic!("{error}"));
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let execution = SemanticExecutionBudget::for_fixpoint(10);
        let mut request =
            SemanticRequest::with_execution_budget(&mut budget, &cancellation, &execution);
        assert!(matches!(
            WantedFieldIndex::new(fields.iter().copied(), || visit_wanted_field_index(
                &mut request
            )),
            Err(SelectedBinderError::Interrupted(
                "semantic traversal budget exhausted"
            ))
        ));
        assert_eq!(execution.work().traversal_steps, 10);
        assert!(execution.work().exhausted);

        // Cancellation during sorting must stop before the index escapes.
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let mut visits = 0;
        assert!(matches!(
            WantedFieldIndex::new(fields.iter().copied(), || {
                visits += 1;
                if visits == fields.len() + 7 {
                    cancellation.cancel();
                }
                visit_wanted_field_index(&mut request)
            }),
            Err(SelectedBinderError::Interrupted("cancelled"))
        ));
        assert_eq!(visits, fields.len() + 7);

        // A completely unrelated query still visits (and charges) its pruned
        // root; no successful empty result can hide exhausted execution work.
        let cancellation = crate::cancellation::CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let execution = SemanticExecutionBudget::for_fixpoint(0);
        let mut request =
            SemanticRequest::with_execution_budget(&mut budget, &cancellation, &execution);
        assert!(matches!(
            index.containing(index_test_span(1000, 1002), || visit_wanted_field_index(
                &mut request
            )),
            Err(SelectedBinderError::Interrupted(
                "semantic traversal budget exhausted"
            ))
        ));
        assert!(execution.work().exhausted);
        cancellation.cancel();
        assert!(matches!(
            index.containing(index_test_span(1000, 1002), || visit_wanted_field_index(
                &mut request
            )),
            Err(SelectedBinderError::Interrupted("cancelled"))
        ));
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
            field_binders: HashMap::new(),
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
            field_binders: HashMap::new(),
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
                host_activation: brokk_bifrost_analysis::analyzer::semantic_model::HostActivationContext::library_none(),
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
                    production_input_digest: None,
                    verified_raw_artifacts: Vec::new(),
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
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: language-rule admission authority was dropped before policy source binding"
    )]
    fn selected_field_authority_survives_set_merges_but_not_projection() {
        use super::super::{
            PipelineValue, SeedMatch, SelectedPatternSourceEvidence,
            detailed_evidence_for_pipeline_value,
        };
        use crate::query::CodeQuery;
        use crate::structural::matcher::{CaptureBinding, match_query};

        let source = "use poem::web::Query as Extract;\nfn h(Extract(value): Extract<u8>) { let _ = value; }\n";
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n[dependencies]\npoem = \"3.1.7\"\n")
            .file("src/lib.rs", source).build();
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
        assert!(matched.diagnostics.is_empty(), "{:?}", matched.diagnostics);
        let [selected] = matched.matches.as_slice() else {
            panic!("one selected binder");
        };
        let SelectedPatternSourceEvidence::Admitted(proof) = &selected.selected_pattern_source
        else {
            panic!("selected field proof");
        };
        let provider = workspace
            .analyzer()
            .structural_fact_providers()
            .into_iter()
            .find(|provider| provider.structural_language() == Language::Rust)
            .expect("Rust facts");
        let facts = provider.structural_facts(&file).expect("facts");
        let query = CodeQuery::from_json(&serde_json::json!({"schema_version": 1, "match": {"kind": "identifier", "name": "value"}})).expect("identifier query");
        let matches = match_query(query.seed().expect("seed"), &facts, 100);
        let mut selected_facts =
            super::super::seeds::language_rule_matches(&facts, matches, &matched.matches);
        assert_eq!(selected_facts.len(), 1);
        let fact_match = selected_facts.pop().expect("field fact");
        let seed = Arc::new(SeedMatch {
            language: Language::Rust,
            file: file.clone(),
            facts: Arc::clone(&facts),
            fact_match,
            python_import: None,
        });
        let mut ordinary = (*seed).clone();
        ordinary.fact_match.selected_pattern_source = Default::default();
        let ordinary = Arc::new(ordinary);
        let admitted = PipelineValue::StructuralMatch(Arc::clone(&seed));
        let plain = PipelineValue::StructuralMatch(ordinary);
        assert_eq!(
            admitted.key(),
            plain.key(),
            "proof is not part of row identity"
        );
        for merge in [
            PipelineValue::merge_evidence as fn(&mut PipelineValue, PipelineValue),
            PipelineValue::merge_intersect_evidence,
        ] {
            for (mut left, right) in [
                (admitted.clone(), plain.clone()),
                (plain.clone(), admitted.clone()),
                (admitted.clone(), admitted.clone()),
            ] {
                merge(&mut left, right);
                let evidence = detailed_evidence_for_pipeline_value(0, &left, Some(source), None);
                let SelectedPatternSourceEvidence::Admitted(retained) =
                    &evidence.selected_pattern_source
                else {
                    panic!("set merge lost authority");
                };
                assert!(
                    Arc::ptr_eq(proof, retained),
                    "the SAME allocation reaches detailed evidence"
                );
            }
            // Independent admission owners conflict even on identical source.
            let other = rule_matches(&workspace, &file, source);
            let mut conflicting = (*seed).clone();
            conflicting.fact_match.selected_pattern_source =
                other.matches[0].selected_pattern_source.clone();
            for (mut left, right) in [
                (
                    admitted.clone(),
                    PipelineValue::StructuralMatch(Arc::new(conflicting.clone())),
                ),
                (
                    PipelineValue::StructuralMatch(Arc::new(conflicting)),
                    admitted.clone(),
                ),
            ] {
                merge(&mut left, right);
                merge(&mut left, plain.clone());
                let evidence = detailed_evidence_for_pipeline_value(0, &left, Some(source), None);
                assert!(matches!(
                    evidence.selected_pattern_source,
                    SelectedPatternSourceEvidence::Conflict
                ));
            }
        }
        let mut projected = seed.fact_match.clone();
        let start = source.rfind("value").expect("different use span");
        projected.captures = vec![CaptureBinding {
            name: "different".into(),
            span: crate::structural::facts::Span {
                start_byte: start,
                end_byte: start + 5,
            },
            text: "value".into(),
            start_line: 2,
            end_line: 2,
            start_column: 0,
            end_column: 5,
            kind: None,
            source_identity: facts.source_identity(),
            node: None,
        }]
        .into();
        let projected =
            super::super::pipeline::capture_anchor_matches(&projected, &facts, "different");
        assert_eq!(projected.len(), 1);
        assert!(matches!(
            projected[0].selected_pattern_source,
            SelectedPatternSourceEvidence::NotRequired
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9925: admitted partial-artifact proofs escaped file windows without retained owner charges"
    )]
    fn selected_proof_owners_cross_file_windows_and_parent_acceptance() {
        use super::super::{CodeQueryExecutionLimits, SelectedPatternSourceEvidence};
        use crate::analyzer::semantic::{
            SemanticArtifactLeaseSet, SemanticCapability, SemanticExecutionBudget, SemanticOutcome,
            SemanticWork,
        };

        fn context<'a>(
            workspace: &'a WorkspaceAnalyzer,
            leases: &SemanticArtifactLeaseSet,
            limits: CodeQuerySemanticLimits,
        ) -> SemanticQueryContext<'a> {
            let budget = SemanticBudget::default();
            let execution = SemanticExecutionBudget::new(10);
            let (before, child) = execution.fork();
            SemanticQueryContext::new_with_parent_scope(
                workspace,
                None,
                limits,
                Default::default(),
                Default::default(),
                Default::default(),
                0,
                None,
                workspace.analyzer().active_semantic_model_snapshot(),
                None,
                None,
                &budget.scope_snapshot(),
                super::super::semantic::semantic_budget_limits(limits),
                super::super::type_flow::CodeQueryRootAllotment::from_execution_limits(
                    &CodeQueryExecutionLimits {
                        semantic: limits,
                        ..Default::default()
                    },
                ),
                before,
                child,
                leases.snapshot(),
            )
        }
        fn proof(
            workspace: &WorkspaceAnalyzer,
            context: &mut SemanticQueryContext<'_>,
            file: &ProjectFile,
            source: &str,
        ) -> Arc<SelectedPatternObservation> {
            let matches = matches_for_file(
                workspace.analyzer(),
                Some(context),
                None,
                file,
                source,
                RustRule::PoemHandlerParam,
            );
            let [matched] = matches.matches.as_slice() else {
                panic!("one source proof: {:?}", matches.diagnostics);
            };
            let SelectedPatternSourceEvidence::Admitted(proof) = &matched.selected_pattern_source
            else {
                panic!("canonical selected source");
            };
            Arc::clone(proof)
        }
        let second = "use poem::web::Query;\nfn h(Query(value): Query<u8>) { let _ = value; }\n";
        let first = format!("mod second;\n{second}");
        let project = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n[dependencies]\npoem = \"3.1.7\"\n")
            .file("src/lib.rs", &first).file("src/second.rs", second).build();
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
        let root = workspace.analyzer().project().root();
        let first_file = ProjectFile::new(root, "src/lib.rs");
        let second_file = ProjectFile::new(root, "src/second.rs");
        let limits = CodeQuerySemanticLimits::default();
        let mut parent = SemanticArtifactLeaseSet::new(limits.max_retained_bytes);
        let mut query = context(&workspace, &parent, limits);
        query.start_artifact_window(first_file.clone());
        let original = proof(&workspace, &mut query, &first_file, &first);
        let partial = SemanticOutcome::Unsupported {
            capability: SemanticCapability::Values,
            partial: Some(Arc::clone(
                original.observation().point().procedure().artifact(),
            )),
            work: SemanticWork::default(),
        };
        assert!(query.retain_selected_pattern_source(&first_file, &original));
        let charged = query.work().retained_bytes;
        assert!(query.retain_selected_pattern_source(&first_file, &original));
        assert_eq!(
            query.work().retained_bytes,
            charged,
            "an exact owner alias has no additional charge"
        );
        let distinct = proof(&workspace, &mut query, &first_file, &first);
        assert!(!Arc::ptr_eq(&original, &distinct));
        assert!(query.retain_selected_pattern_source(&first_file, &distinct));
        assert!(
            query.work().retained_bytes > charged,
            "equal source in a distinct proof allocation consumes memory"
        );
        query.release_artifact_window();
        assert!(query.can_start_artifact_windows());
        query.start_artifact_window(second_file.clone());
        let other = proof(&workspace, &mut query, &second_file, second);
        assert!(query.retain_selected_pattern_source(&second_file, &other));
        query.release_artifact_window();
        let (_, _, _, charge) = query.into_receipt().expect("query receipt").into_parts();
        parent
            .try_apply_charge(charge, 0)
            .expect("atomic parent acceptance");
        assert!(
            !partial.is_complete(),
            "allocation accounting does not promote partial quality"
        );
        assert!(
            parent
                .snapshot()
                .contains_exact(partial.available_value().expect("partial artifact"))
        );
        assert!(
            parent
                .snapshot()
                .contains_exact(other.observation().point().procedure().artifact())
        );
        let mut owners = 0;
        parent.snapshot().census_owners(|_| owners += 1);
        assert_eq!(
            owners, 3,
            "both file windows handed their actual proof owners to the caller"
        );

        let tight = CodeQuerySemanticLimits {
            max_retained_bytes: parent.retained_bytes() + 1,
            ..limits
        };
        let mut next = context(&workspace, &parent, tight);
        assert!(
            next.retain_selected_pattern_source(&first_file, &original),
            "inherited owner is already charged"
        );
        // Produce a separate admission outside the restricted query to test
        // the retained-owner boundary independently of source preparation.
        let mut unbounded = context(&workspace, &parent, limits);
        let rejected = proof(&workspace, &mut unbounded, &first_file, &first);
        assert!(!next.retain_selected_pattern_source(&first_file, &rejected));
        assert!(
            next.take_diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code
                    == super::super::CodeQueryDiagnosticCode::SemanticBudgetExhausted)
        );
        next.release_artifact_window();
        let (_, _, _, charge) = next
            .into_receipt()
            .expect("refused query receipt")
            .into_parts();
        assert!(
            charge.is_empty(),
            "refusal publishes no owner or artifact addition"
        );
        owners = 0;
        parent.snapshot().census_owners(|_| owners += 1);
        assert_eq!(owners, 3);
        let pinned = Arc::downgrade(&original);
        drop(original);
        drop(distinct);
        drop(other);
        assert!(
            pinned.upgrade().is_some(),
            "parent charge pins every pointer record's allocation"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#12555: the unresolved-constructor prefilter masked the admission's named alias limit"
    )]
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
            field_binders: HashMap::new(),
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
        // The root is Some and the selected inner field is Query's field 0.
        // The full recorded path must be checked before admitting that source.
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
        let spans = matched
            .matches
            .iter()
            .map(|matched| &source[matched.select.start_byte..matched.select.end_byte])
            .collect::<Vec<_>>();
        assert_eq!(spans, ["x"], "{:?}", matched.diagnostics);
        assert!(matched.diagnostics.is_empty(), "{:?}", matched.diagnostics);
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
    #[brokk_bifrost_test_macros::hardwon(
        "#12555: the unresolved-constructor prefilter masked the admission's named syntax limit"
    )]
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
