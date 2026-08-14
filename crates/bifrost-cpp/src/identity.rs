//! Which C++ callable is which: declaration/definition roles, the linkage
//! evidence that unifies a header declaration with its `.cpp` definition, and
//! the #1134 resolution-time identity reconciliation built on top of both.
//!
//! Two things stay in `analyzer/cpp/identity.rs` on purpose:
//!
//! * [`cpp_header_body_files_are_related`] here takes the implementation file's
//!   `#include` lines and the include-target index as arguments. The analysis
//!   wrapper of the same name owns the `resolve_analyzer::<CppAnalyzer>`
//!   downcast that produces them, because the searchtools identity block reaches
//!   this predicate through `&dyn IAnalyzer` and there is no capability that
//!   carries an `IncludeTargetIndex`.
//! * The moka cells that memoize [`cpp_reconcile_candidates`] per member
//!   identifier and [`cpp_reconcile_group`] per [`CppReconcileGroupKey`] stay
//!   on the analyzer, as does every other cache, so `IAnalyzer::update` keeps
//!   rebuilding them wholesale.

use crate::declarations::{cpp_file_using_namespaces, cpp_member_fq, node_text};
use crate::graph::resolver::{
    cpp_type_name_components, declarator_name_node, qualified_name_has_concrete_scope_separators,
};
use crate::graph_support::CppSource;
use crate::imports::{IncludeTargetIndex, include_paths, resolve_include_targets_with_index};
use crate::reconcile::{ReconciledIdentity, VisibleClass, reconcile_out_of_line_member_identity};
use brokk_bifrost_core::analyzer::fq_name::{SegmentKind, segment_interner};
use brokk_bifrost_core::analyzer::model::{CallableLinkage, Range};
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq;
use brokk_bifrost_core::analyzer::tree_walk::{node_for_exact_range, subtree_contains};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_core::profiling;
use std::collections::BTreeSet;
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppCallableUnitRole {
    DeclarationOnly,
    Definition,
    Both,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppOccurrenceRole {
    DeclarationOnly,
    Definition,
    Both,
    Unknown,
}

impl CppOccurrenceRole {
    pub fn api_label(self) -> Option<&'static str> {
        match self {
            Self::DeclarationOnly => Some("declaration"),
            Self::Definition => Some("definition"),
            Self::Both | Self::Unknown => None,
        }
    }
}

pub struct CppOccurrenceClassifier {
    tree: Tree,
}

impl CppOccurrenceClassifier {
    pub fn new(source: &str) -> Option<Self> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .ok()?;
        parser.parse(source, None).map(|tree| Self { tree })
    }

    pub fn classify(&self, candidate: &CodeUnit, range: &Range) -> CppOccurrenceRole {
        cpp_occurrence_role_for_range(self.tree.root_node(), candidate, range)
    }
}

pub fn cpp_callable_unit_role(
    index: &dyn CodeUnitIndex,
    callable: &CodeUnit,
) -> CppCallableUnitRole {
    if !callable.is_callable() {
        return CppCallableUnitRole::Unknown;
    }
    let mut declaration = false;
    let mut definition = false;
    for metadata in index.signature_metadata(callable) {
        if metadata.is_declaration_only() {
            declaration = true;
        } else {
            definition = true;
        }
    }
    match (declaration, definition) {
        (true, false) => CppCallableUnitRole::DeclarationOnly,
        (false, true) => CppCallableUnitRole::Definition,
        (true, true) => CppCallableUnitRole::Both,
        (false, false) => CppCallableUnitRole::Unknown,
    }
}

pub fn cpp_indexed_callable_linkage(
    index: &dyn CodeUnitIndex,
    callable: &CodeUnit,
) -> Option<CallableLinkage> {
    let mut external = false;
    for metadata in index.signature_metadata(callable) {
        match metadata.callable_linkage() {
            Some(CallableLinkage::Internal) => return Some(CallableLinkage::Internal),
            Some(CallableLinkage::External) => external = true,
            None => {}
        }
    }
    external.then_some(CallableLinkage::External)
}

/// Whether `left` and `right` are the same callable seen twice.
///
/// `header_body_related` is the include-evidence predicate; the analysis wrapper
/// supplies it because reaching an `IncludeTargetIndex` needs the analyzer
/// downcast this crate cannot perform.
pub fn cpp_callable_definitions_share_identity_evidence(
    index: &dyn CodeUnitIndex,
    left: &CodeUnit,
    right: &CodeUnit,
    header_body_related: impl Fn(&ProjectFile, &ProjectFile) -> bool,
) -> bool {
    left.source() == right.source()
        || (left.fq_name() == right.fq_name()
            && left.signature() == right.signature()
            && matches!(
                cpp_indexed_callable_linkage(index, left),
                Some(CallableLinkage::External)
            )
            && matches!(
                cpp_indexed_callable_linkage(index, right),
                Some(CallableLinkage::External)
            )
            && header_body_related(left.source(), right.source()))
}

/// Return whether `node` is one of the names declared by a range-for
/// declarator. Follow only declarator fields. This keeps identifiers in array
/// bounds and attributes in the range-for header as references.
pub fn cpp_is_range_for_binding_name(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        let Some(parent) = candidate.parent() else {
            return false;
        };
        if parent.kind() == "for_range_loop" {
            return parent
                .child_by_field_name("declarator")
                .is_some_and(|declarator| {
                    cpp_range_for_declarator_contains_name(declarator, node)
                });
        }
        current = Some(parent);
    }
    false
}

/// Return whether `node` is the declarator name of a constructor or destructor
/// -- the declaration occurrence itself, never a reference to one.
///
/// A declaration site is not a usage probe, so the reference differential must
/// not seed one (#1834). The indexed-declaration-name filter the seeder already
/// applies misses these two shapes:
///
/// * The identifier inside a `destructor_name`. The census proposes both
///   `~Foo` and its inner `Foo`, while the indexed declaration name range
///   covers only the `~Foo` span, so the inner identifier survives the filter.
/// * A declarator the parse never recovered as a declaration. `class MACRO Foo
///   { ... }` and a bare `MACRO_NAMESPACE_BEGIN` before `class Foo { ... }`
///   both recover as a `function_definition` whose declarator is a lone
///   identifier -- a shape valid C++ cannot produce -- with the class body as
///   its `compound_statement`. Every declaration inside it that the grammar can
///   read as an expression becomes one, so `Foo();` reads as a call of `Foo`,
///   which the census then grades as a tier-1 forward gap.
///
/// Both tests are structural. Constructor calls stay references: `new Foo(...)`
/// is a `new_expression` type, `Foo x(...)` is a declaration whose type field
/// holds the name, and `: base_(x)` is a `field_initializer`. None of them is a
/// `function_declarator` declarator or a callee inside a recovered class body.
pub fn cpp_is_constructor_or_destructor_declarator_name(node: Node<'_>, source: &str) -> bool {
    cpp_is_declared_constructor_or_destructor_name(node)
        || cpp_is_recovered_constructor_or_destructor_name(node, source)
}

/// The parsed-as-declared shape: the grammar's `constructor_or_destructor_
/// declaration` and `constructor_or_destructor_definition`, both aliased to
/// `declaration`/`function_definition` and both recognizable by the absence of
/// a `type` field -- exactly what distinguishes a constructor or destructor
/// from every other C++ callable, which must name a return type.
fn cpp_is_declared_constructor_or_destructor_name(node: Node<'_>) -> bool {
    let mut name = node;
    if let Some(parent) = name.parent()
        && parent.kind() == "destructor_name"
    {
        name = parent;
    }
    // `Foo::Foo`, `A::B::Foo` and `Foo<T>::~Foo` reach the declarator through
    // the qualified name's `name` field. The `scope` segments stay references:
    // they name the owning type.
    while let Some(parent) = name.parent() {
        if parent.kind() != "qualified_identifier"
            || parent.child_by_field_name("name") != Some(name)
        {
            break;
        }
        name = parent;
    }
    let Some(declarator) = name.parent() else {
        return false;
    };
    if declarator.kind() != "function_declarator"
        || declarator.child_by_field_name("declarator") != Some(name)
    {
        return false;
    }
    let Some(owner) = declarator.parent() else {
        return false;
    };
    matches!(owner.kind(), "declaration" | "function_definition")
        && owner.child_by_field_name("declarator") == Some(declarator)
        && owner.child_by_field_name("type").is_none()
}

/// The recovered shape: a callee that names the class whose body the parse
/// turned into a `compound_statement`.
///
/// Two conditions hold together, and both are needed. The nearest enclosing
/// `function_definition` must declare a bare `identifier` -- valid C++ always
/// declares a `function_declarator` there, so this shape only ever comes out of
/// the class-body recovery. And the callee must name one of the identifiers in
/// that recovery's header, which is where the class name is: `class MACRO Foo`
/// and `class MACRO Foo : public Base` both keep `Foo` in the header even
/// though the second leaves `Base` as the recovered declarator.
///
/// Together they keep genuine calls references. A recursive `f(n - 1);` sits in
/// a real body, whose declarator is a `function_declarator`. A method body
/// inside the recovered class body is itself a real `function_definition`, so
/// `RAPIDJSON_ASSERT(false)` inside one keeps its own nearest owner. A macro
/// invocation such as `DISALLOW_COPY_AND_ASSIGN(Foo);` in the recovered body
/// does not name the class, so it stays proposed.
fn cpp_is_recovered_constructor_or_destructor_name(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(call) = node.parent() else {
        return false;
    };
    if call.kind() != "call_expression" || call.child_by_field_name("function") != Some(node) {
        return false;
    }
    let mut current = call.parent();
    while let Some(ancestor) = current {
        if ancestor.kind() == "function_definition" {
            return ancestor
                .child_by_field_name("declarator")
                .is_some_and(|declarator| declarator.kind() == "identifier")
                && cpp_recovered_class_header_names(ancestor, node_text(node, source), source);
        }
        current = ancestor.parent();
    }
    false
}

/// Whether `name` is spelled by an identifier in the recovered class header --
/// everything the recovery kept before the body it mistook for a function body.
fn cpp_recovered_class_header_names(definition: Node<'_>, name: &str, source: &str) -> bool {
    let header_end = definition
        .child_by_field_name("body")
        .map_or_else(|| definition.end_byte(), |body| body.start_byte());
    let mut stack = vec![definition];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= header_end {
            continue;
        }
        if matches!(
            node.kind(),
            "identifier" | "type_identifier" | "namespace_identifier"
        ) && node_text(node, source) == name
        {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn cpp_range_for_declarator_contains_name(declarator: Node<'_>, target: Node<'_>) -> bool {
    let mut pending = vec![declarator];
    while let Some(candidate) = pending.pop() {
        match candidate.kind() {
            "identifier" | "field_identifier" => {
                if cpp_same_node(candidate, target) {
                    return true;
                }
            }
            "structured_binding_declarator" => {
                let mut cursor = candidate.walk();
                if candidate
                    .named_children(&mut cursor)
                    .any(|name| cpp_same_node(name, target))
                {
                    return true;
                }
            }
            "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "attributed_declarator"
            | "parenthesized_declarator"
            | "function_declarator"
            | "init_declarator" => {
                if let Some(inner) = cpp_range_for_inner_declarator(candidate) {
                    pending.push(inner);
                }
            }
            _ => {}
        }
    }
    false
}

fn cpp_range_for_inner_declarator(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("declarator").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "identifier"
                    | "field_identifier"
                    | "structured_binding_declarator"
                    | "pointer_declarator"
                    | "reference_declarator"
                    | "array_declarator"
                    | "attributed_declarator"
                    | "parenthesized_declarator"
                    | "function_declarator"
                    | "init_declarator"
            )
        })
    })
}

fn cpp_same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.id() == right.id()
        && left.start_byte() == right.start_byte()
        && left.end_byte() == right.end_byte()
}

/// Direct include evidence relates one header declaration to one implementation
/// file without pretending that every external name in a workspace belongs to
/// one linker unit.
///
/// `implementation_imports` are that file's raw `#include` lines; the analysis
/// wrapper reads them off the analyzer along with `include_targets`.
pub fn cpp_header_body_files_are_related(
    left: &ProjectFile,
    right: &ProjectFile,
    implementation_imports: &[String],
    include_targets: &IncludeTargetIndex,
) -> bool {
    let (header, implementation) = if cpp_source_path_is_header(left) {
        (left, right)
    } else if cpp_source_path_is_header(right) {
        (right, left)
    } else {
        return false;
    };
    if cpp_source_path_is_header(implementation) {
        return false;
    }
    implementation_imports
        .iter()
        .flat_map(|import| include_paths(std::slice::from_ref(import)))
        .any(|include| {
            let targets =
                resolve_include_targets_with_index(implementation, &include, include_targets);
            targets.len() == 1 && targets.first() == Some(header)
        })
}

/// Which of `left`/`right` the include evidence would read as the header, if
/// either. The analysis wrapper uses this to decide which file's imports to read
/// before paying for them.
pub fn cpp_header_body_implementation_file<'a>(
    left: &'a ProjectFile,
    right: &'a ProjectFile,
) -> Option<&'a ProjectFile> {
    let implementation = if cpp_source_path_is_header(left) {
        right
    } else if cpp_source_path_is_header(right) {
        left
    } else {
        return None;
    };
    (!cpp_source_path_is_header(implementation)).then_some(implementation)
}

pub fn cpp_source_path_is_header(source: &ProjectFile) -> bool {
    let path = rel_path_string(source).to_ascii_lowercase();
    matches!(path.rsplit('.').next(), Some("h" | "hh" | "hpp" | "hxx"))
}

pub fn cpp_occurrence_role_for_range(
    root: Node<'_>,
    candidate: &CodeUnit,
    range: &Range,
) -> CppOccurrenceRole {
    if !candidate.is_callable() && !candidate.is_class() {
        return CppOccurrenceRole::Both;
    }
    let Some(node) = cpp_declaration_node_for_range(root, range) else {
        return CppOccurrenceRole::Unknown;
    };
    if candidate.is_callable() {
        return if subtree_contains(node, |descendant| {
            descendant.kind() == "function_definition"
                && descendant.child_by_field_name("body").is_some()
        }) {
            CppOccurrenceRole::Definition
        } else {
            CppOccurrenceRole::DeclarationOnly
        };
    }
    if node.kind() == "function_definition" && node.child_by_field_name("body").is_some() {
        return CppOccurrenceRole::Definition;
    }
    if !subtree_contains(node, |descendant| {
        matches!(
            descendant.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        )
    }) {
        return CppOccurrenceRole::Both;
    }
    if subtree_contains(node, |descendant| {
        matches!(
            descendant.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        ) && descendant.child_by_field_name("body").is_some()
    }) {
        CppOccurrenceRole::Definition
    } else {
        CppOccurrenceRole::DeclarationOnly
    }
}

fn cpp_declaration_node_for_range<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>> {
    node_for_exact_range(root, range).or_else(|| {
        root.descendant_for_byte_range(range.start_byte, range.end_byte)
            .and_then(|mut node| {
                while node.start_byte() > range.start_byte || node.end_byte() < range.end_byte {
                    node = node.parent()?;
                }
                Some(node)
            })
    })
}

/// The #1134 resolution-time identity-reconciliation overlay for one queried
/// canonical `fq_name`.
///
/// For each out-of-line member definition whose per-file provisional identity
/// the include-visible class table re-keys to this name, it holds a *re-keyed*
/// `CodeUnit` -- a synthetic unit carrying the canonical identity but the
/// definition's real `.cpp` source -- so a canonical query resolves the
/// definition alongside its header declaration across every resolution surface
/// (`definitions`, source blocks, occurrence roles, canonical selectors). The
/// re-keyed unit is not in the store, so `provisional_of` maps it back to the
/// stored provisional unit for range and signature-metadata lookups.
#[derive(Default)]
pub struct CppReconciledDefinitionIndex {
    /// Re-keyed definitions belonging under the queried canonical `fq_name`.
    pub rekeyed: Vec<CodeUnit>,
    /// Re-keyed unit -> the stored provisional unit its indexed data lives under.
    pub provisional_of: HashMap<CodeUnit, CodeUnit>,
}

/// Which candidates one reconcile group covers: a member identifier, and the
/// terminal owner component that #1566's pre-filter admits.
///
/// This -- not the queried fq name -- is the unit reconciliation is a function
/// of, and keying the memo by it is the #1908 fix. The old key was the queried
/// fq name, so a bare identifier that 1,277 distinct owners answer produced
/// 1,277 distinct keys, none of which ever hit, each re-running the identical
/// `lookup_candidates_by_identifier` store read and re-scanning the identical
/// 2,898-candidate set: 3.70M candidate evaluations for one request.
///
/// The owner terminal stays in the key rather than being dropped for a plain
/// per-identifier map. Dropping it would mean reconciling every same-named
/// candidate in the workspace on the first query for that identifier, which is
/// exactly the cost #1566 removed -- chromium paid ~75 s per member query that
/// way. `reconcile_skips_same_named_members_of_unrelated_classes_1566` pins it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CppReconcileGroupKey {
    /// The queried name's terminal segment: the member identifier the
    /// persisted identifier index is probed with.
    pub member_identifier: String,
    /// The terminal component of the queried name's penultimate segment, or
    /// `None` for a single-segment (bare) query, where #1566's pre-filter is
    /// inert and every candidate has to be reconciled.
    pub owner_terminal: Option<String>,
}

/// Which member identifier and owner terminal a queried canonical name asks
/// about, or `None` when the name has no terminal segment to probe with.
///
/// Parsed through the sanctioned input-edge parser rather than split here, and
/// note `$` is not a segment boundary for it -- a nested owner chain stays one
/// segment, so the terminal really is the member.
pub fn cpp_reconcile_group_key(fq_name: &str) -> Option<CppReconcileGroupKey> {
    let interner = segment_interner();
    let query_fq = parse_symbol_path_fq(Language::Cpp, fq_name, interner);
    let (member_identifier, _) = interner.resolve(query_fq.last()?);
    if member_identifier.is_empty() {
        return None;
    }
    // #1566 owner-terminal pre-filter: the reconciler only re-partitions a
    // candidate's qualifier -- the class chain it emits is always a suffix
    // of the candidate's owner segments (`reconcile.rs`) -- so the terminal
    // `$` component of any identity it can produce equals the candidate's
    // terminal owner segment. A candidate whose terminal owner differs
    // from the queried name's penultimate segment can therefore never
    // re-key onto it, and skipping it avoids the role check and, on
    // whale repos, an include-closure class-table build per same-named
    // candidate in the repo.
    let owner_terminal = query_fq.segments().len().checked_sub(2).map(|penultimate| {
        let (text, _) = interner.resolve(query_fq.segments()[penultimate]);
        // fqname-M4: the input-edge parser above deliberately keeps a nested
        // owner chain as one `$`-joined segment (no structured sub-segments
        // exist at this surface), so the terminal component must come from
        // the raw text.
        text.rsplit_once('$')
            .map_or(text, |(_, tail)| tail)
            .to_string()
    });
    Some(CppReconcileGroupKey {
        member_identifier: member_identifier.to_string(),
        owner_terminal,
    })
}

/// Every callable declaration in the workspace sharing one member identifier,
/// bucketed by its terminal owner segment.
///
/// One store read and one pass over the candidate set per identifier, memoized
/// on the analyzer. Before #1908 both were re-run once per queried fq name.
pub struct CppReconcileCandidates {
    by_owner_terminal: HashMap<String, Vec<CodeUnit>>,
    /// Every bucketed candidate, in the order the sorted candidate set
    /// produced them. What a bare query has to reconcile, since #1566's
    /// pre-filter cannot narrow it.
    all: Vec<CodeUnit>,
}

impl CppReconcileCandidates {
    /// The candidates a group key admits: one owner-terminal bucket, or every
    /// candidate for a bare query.
    fn for_group(&self, key: &CppReconcileGroupKey) -> &[CodeUnit] {
        match &key.owner_terminal {
            Some(owner_terminal) => self
                .by_owner_terminal
                .get(owner_terminal)
                .map_or(&[][..], Vec::as_slice),
            None => &self.all,
        }
    }

    /// Every bucketed candidate, once. What a cache weigher has to charge for.
    pub fn iter(&self) -> impl Iterator<Item = &CodeUnit> {
        self.all.iter()
    }

    /// How many bucket entries reference those candidates. A candidate with no
    /// owner segment is in no bucket, so this is not `len`.
    pub fn bucketed_len(&self) -> usize {
        self.by_owner_terminal.values().map(Vec::len).sum()
    }
}

/// Read and bucket every callable declaration sharing `member_identifier`.
///
/// `keep_going` is polled per candidate batch; `None` means the caller's
/// deadline expired and nothing may be memoized, because a truncated candidate
/// set is indistinguishable from an identifier with fewer namesakes and every
/// later reconcile reading it would silently lose definitions (#1908 fix D,
/// the same contract `visible_type_units_while` carries).
pub fn cpp_reconcile_candidates(
    cpp: &dyn CppSource,
    member_identifier: &str,
    keep_going: &dyn Fn() -> bool,
) -> Option<CppReconcileCandidates> {
    let candidates: BTreeSet<CodeUnit> = {
        let _lookup =
            profiling::scope_with(|| format!("cpp.reconcile.lookup[{member_identifier}]"));
        cpp.lookup_candidates_by_identifier(member_identifier)
    };
    profiling::note_with(|| {
        format!(
            "cpp.reconcile.candidates[{member_identifier}] n={}",
            candidates.len()
        )
    });

    let interner = segment_interner();
    let mut by_owner_terminal: HashMap<String, Vec<CodeUnit>> = HashMap::default();
    let mut all = Vec::new();
    for (index, unit) in candidates.into_iter().enumerate() {
        // Bucketing is a segment walk per candidate, cheap next to the role
        // check and class-table build the groups pay, so the poll runs per
        // batch rather than per candidate.
        if index % CANDIDATE_BUCKETING_POLL_STRIDE == 0 && !keep_going() {
            return None;
        }
        if !unit.is_callable() {
            continue;
        }
        let owner_terminal = unit
            .fq()
            .segments()
            .iter()
            .filter_map(|&segment| {
                let (text, kind) = interner.resolve(segment);
                // Candidate fq segments carry real boundaries (each nested
                // class is its own `SegmentKind::Nested` segment), so the
                // segment text is already the terminal component.
                matches!(
                    kind,
                    SegmentKind::Package | SegmentKind::Type | SegmentKind::Nested
                )
                .then_some(text)
            })
            .last();
        if let Some(owner_terminal) = owner_terminal {
            by_owner_terminal
                .entry(owner_terminal.to_string())
                .or_default()
                .push(unit.clone());
        }
        all.push(unit);
    }
    Some(CppReconcileCandidates {
        by_owner_terminal,
        all,
    })
}

/// How many candidates the bucketing pass walks between deadline polls.
const CANDIDATE_BUCKETING_POLL_STRIDE: usize = 256;

/// Reconcile every candidate one group key admits, grouped by the canonical
/// `fq_name` each re-keyed definition belongs under.
///
/// Deliberately **not** a workspace-wide index: building one would need a full
/// declaration scan, and a warm forward lookup must not trigger one
/// (`tests/analyzer_persistence.rs`'s candidate-bounded contract). Instead each
/// group reconciles only the candidates the persisted terminal identifier
/// index already offers, which is the same bounded lookup the ordinary
/// resolution path uses.
///
/// A definition whose reconciled identity equals its provisional one (the
/// overwhelming majority, including genuine `ns1::ns2::Klass::method` namespace
/// chains) contributes nothing.
///
/// `None` means `keep_going` went false mid-scan. Nothing may be memoized
/// then; see [`cpp_reconcile_candidates`].
pub fn cpp_reconcile_group(
    cpp: &dyn CppSource,
    key: &CppReconcileGroupKey,
    candidates: &CppReconcileCandidates,
    keep_going: &dyn Fn() -> bool,
    on_candidate: &dyn Fn(),
) -> Option<HashMap<String, Arc<CppReconciledDefinitionIndex>>> {
    let _scope = profiling::scope_with(|| {
        format!(
            "cpp.reconciled.build[{}#{}]",
            key.member_identifier,
            key.owner_terminal.as_deref().unwrap_or("*")
        )
    });
    let mut groups: HashMap<String, CppReconciledDefinitionIndex> = HashMap::default();
    let mut using_by_file: HashMap<ProjectFile, Arc<Vec<String>>> = HashMap::default();
    for unit in candidates.for_group(key) {
        // Per candidate, not per batch: each iteration below can run a role
        // check (0.265 ms mean in the #1908 trace) and an include-visible
        // class-table read, so an atomic load per iteration is free by
        // comparison.
        if !keep_going() {
            return None;
        }
        on_candidate();
        // Lazy: `fq_name` clones a String, and this loop runs once per
        // same-named candidate the group admits.
        let _candidate =
            profiling::scope_with(|| format!("cpp.reconcile.candidate[{}]", unit.fq_name()));
        let role = {
            let _role = profiling::scope("cpp.reconcile.role");
            cpp_callable_unit_role(cpp, unit)
        };
        if !matches!(
            role,
            CppCallableUnitRole::Definition | CppCallableUnitRole::Both
        ) {
            continue;
        }
        let Some(reconciled) = cpp_reconcile_definition_identity(cpp, unit, &mut using_by_file)
        else {
            continue;
        };
        let canonical_fq = reconciled.fq_name();
        // A candidate that already carries the canonical identity is the
        // stored declaration, not a re-keying of it. Before #1908 this read
        // `unit.fq_name() == fq_name` against the queried name, checked before
        // the reconcile; against the group's canonical key it is the same
        // predicate for the same (query, candidate) pair, because a candidate
        // only ever lands under its own reconciled identity.
        if unit.fq_name() == canonical_fq {
            continue;
        }
        // Re-key onto the canonical identity while keeping the definition's
        // real `.cpp` source and signature, so it resolves as a definition
        // alongside its header declaration under the canonical `fq_name`.
        // The structured `FqName` is rebuilt from the *canonical* package and
        // owner chain through the same emission helper extraction uses, so
        // the re-keyed unit carries real segment boundaries: owner lookup
        // (`default_parent_fq_name`) is a pure segment pop, where an empty
        // `fq` would mean "no owner" rather than "not yet migrated".
        let short_name = format!("{}.{}", reconciled.owner_chain, reconciled.member);
        let fq = cpp_member_fq(&reconciled.package, &short_name);
        let rekeyed = CodeUnit::with_signature_and_fq(
            unit.source().clone(),
            unit.kind(),
            reconciled.package,
            short_name,
            unit.signature().map(str::to_string),
            unit.is_synthetic(),
            fq,
        );
        let index = groups.entry(canonical_fq).or_default();
        index.rekeyed.push(rekeyed.clone());
        index.provisional_of.insert(rekeyed, unit.clone());
    }
    Some(
        groups
            .into_iter()
            .map(|(canonical_fq, index)| (canonical_fq, Arc::new(index)))
            .collect(),
    )
}

/// Reconcile one out-of-line member definition's provisional identity against
/// the class table visible to its file. Returns `None` for anything that is
/// not a re-keyable out-of-line member or that the class table does not
/// confirm. A one-segment class qualifier is valid when a structured using
/// namespace and the visible class table confirm its package.
fn cpp_reconcile_definition_identity(
    cpp: &dyn CppSource,
    unit: &CodeUnit,
    using_by_file: &mut HashMap<ProjectFile, Arc<Vec<String>>>,
) -> Option<ReconciledIdentity> {
    // Read the full source-order qualifier off the definition's *structured*
    // `FqName` -- the namespace (`Package`) segments followed by the
    // class-nesting (`Type`/`Nested`) ones, with the terminal `Member` as the
    // member name. The segment boundaries were recorded at extraction, so
    // nothing here re-infers them by splitting the rendered name on a guessed
    // delimiter (the shape `tests/no_stringly_name_parsing.rs` guards). The
    // reconciler then re-partitions this whole sequence against the class
    // table, so extraction need not have decided where the namespace ends and
    // the class chain begins.
    let interner = segment_interner();
    let mut provisional_owner_segments: Vec<&str> = Vec::new();
    let mut member: Option<&str> = None;
    for &segment in unit.fq().segments() {
        let (text, kind) = interner.resolve(segment);
        match kind {
            SegmentKind::Package | SegmentKind::Type | SegmentKind::Nested => {
                // A `Member` is always terminal in a cpp callable's chain; a
                // qualifier segment after one would mean the identity is not
                // the plain `namespace... class... member` shape this handles.
                if member.is_some() {
                    return None;
                }
                if !text.is_empty() {
                    provisional_owner_segments.push(text);
                }
            }
            SegmentKind::Member => member = Some(text),
            _ => return None,
        }
    }
    let member = member?;
    // Existing multi-segment reconciliation uses the provisional structured
    // FqName because it preserves template-owner normalization. Read the
    // declarator only for the previously unsupported one-segment shape, where
    // extraction can prepend a guessed using namespace.
    let structured_owner_segments =
        cpp_structured_out_of_line_owner_segments(cpp, unit).filter(|segments| segments.len() == 1);
    let owner_segments = structured_owner_segments.as_ref().map_or_else(
        || provisional_owner_segments,
        |segments| segments.iter().map(String::as_str).collect(),
    );
    if owner_segments.is_empty() {
        return None;
    }

    let using = using_by_file
        .entry(unit.source().clone())
        .or_insert_with(|| {
            Arc::new(
                cpp.file_source(unit.source())
                    .map(|source| cpp_file_using_namespaces(&source))
                    .unwrap_or_default(),
            )
        })
        .clone();
    let mut namespace_candidates: Vec<&str> = vec![""];
    namespace_candidates.extend(using.iter().map(String::as_str));

    let visible = {
        let _visible = profiling::scope_with(|| {
            format!("cpp.reconcile.visible[{}]", rel_path_string(unit.source()))
        });
        cpp.visible_type_units(unit.source())
    };
    let class_table: Vec<VisibleClass> = visible
        .iter()
        .filter(|candidate| candidate.is_class())
        .map(|candidate| VisibleClass {
            package: candidate.package_name(),
            nested_short_name: candidate.short_name(),
        })
        .collect();

    reconcile_out_of_line_member_identity(
        &owner_segments,
        member,
        &namespace_candidates,
        &class_table,
    )
}

/// Read the owner qualifier from the definition declarator itself.
///
/// Per-file extraction can prepend one guessed using namespace to a bare
/// `Class::member` definition. That provisional package is not source syntax.
/// Reconciliation must compare the real qualifier against every structured
/// using target and let the visible class table select the namespace.
fn cpp_structured_out_of_line_owner_segments(
    cpp: &dyn CppSource,
    unit: &CodeUnit,
) -> Option<Vec<String>> {
    let prepared = cpp.prepared_syntax(unit.source())?;
    let root = prepared.tree().root_node();
    for range in cpp.ranges(unit) {
        let mut current = cpp_declaration_node_for_range(root, &range)?;
        let function = loop {
            if current.kind() == "function_definition" {
                break current;
            }
            current = current.parent()?;
        };
        if function.child_by_field_name("body").is_none() {
            continue;
        }
        let declarator = function.child_by_field_name("declarator")?;
        let name = declarator_name_node(declarator)?;
        if !qualified_name_has_concrete_scope_separators(name) {
            continue;
        }
        let mut components = cpp_type_name_components(name, prepared.source())?;
        components.pop()?;
        if !components.is_empty() {
            return Some(components);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cpp(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("cpp language");
        parser.parse(source, None).expect("cpp tree")
    }

    fn is_declarator_name(tree: &Tree, source: &str, start: usize, text: &str) -> bool {
        let end = start + text.len();
        assert_eq!(&source[start..end], text, "the probe must name the token");
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, end)
            .expect("a node spans the probed range");
        assert_eq!(
            (node.start_byte(), node.end_byte()),
            (start, end),
            "the probed range must be exactly one node: {}",
            node.to_sexp()
        );
        cpp_is_constructor_or_destructor_declarator_name(node, source)
    }

    /// The parsed-as-declared shape, in class and out of line. The names that
    /// surround a declarator stay references: the owning scope of an out-of-line
    /// definition, a parameter type that happens to be the class, and the class
    /// name itself.
    #[test]
    fn declared_constructor_and_destructor_declarator_names_are_not_references() {
        let source = concat!(
            "class Foo {\n",
            "public:\n",
            "  Foo();\n",
            "  Foo(const Foo&);\n",
            "  ~Foo();\n",
            "  void m();\n",
            "};\n",
            "Foo::Foo() {}\n",
            "Foo::~Foo() {}\n",
            "void Foo::m() {}\n",
        );
        let tree = parse_cpp(source);

        for (label, start, text) in [
            (
                "constructor declaration",
                source.find("Foo();").expect("ctor"),
                "Foo",
            ),
            (
                "copy constructor declaration",
                source.find("Foo(const Foo&);").expect("copy ctor"),
                "Foo",
            ),
            (
                "destructor name",
                source.find("~Foo();").expect("dtor"),
                "~Foo",
            ),
            (
                "identifier inside the destructor name",
                source.find("~Foo();").expect("dtor") + "~".len(),
                "Foo",
            ),
            (
                "out-of-line constructor definition name",
                source.find("Foo::Foo() {}").expect("out-of-line ctor") + "Foo::".len(),
                "Foo",
            ),
            (
                "out-of-line destructor definition name",
                source.find("Foo::~Foo() {}").expect("out-of-line dtor") + "Foo::".len(),
                "~Foo",
            ),
        ] {
            assert!(
                is_declarator_name(&tree, source, start, text),
                "the {label} at byte {start} is a declaration occurrence"
            );
        }

        for (label, start, text) in [
            (
                "class name",
                source.find("class Foo {").expect("class") + "class ".len(),
                "Foo",
            ),
            (
                "parameter type",
                source.find("const Foo&").expect("parameter type") + "const ".len(),
                "Foo",
            ),
            (
                "owning scope of an out-of-line constructor",
                source.find("Foo::Foo() {}").expect("out-of-line ctor"),
                "Foo",
            ),
            (
                "owning scope of an out-of-line destructor",
                source.find("Foo::~Foo() {}").expect("out-of-line dtor"),
                "Foo",
            ),
            (
                "out-of-line method name",
                source.find("void Foo::m() {}").expect("out-of-line method") + "void Foo::".len(),
                "m",
            ),
        ] {
            assert!(
                !is_declarator_name(&tree, source, start, text),
                "the {label} at byte {start} stays a reference"
            );
        }
    }

    /// Constructor CALL sites are references. `new D(...)`, the direct
    /// initialization `D x(...)`, a member initializer and a bare temporary
    /// statement all name the type, and none of them is a declarator.
    #[test]
    fn constructor_call_sites_stay_references() {
        let source = concat!(
            "struct B { B(int); };\n",
            "struct D : B {\n",
            "  D(int x) : B(x), base_(x) {}\n",
            "  int base_;\n",
            "};\n",
            "void g() {\n",
            "  D* p = new D(1);\n",
            "  D x(2);\n",
            "  D(3);\n",
            "  g();\n",
            "}\n",
        );
        let tree = parse_cpp(source);

        let inline_declarator = source.find("D(int x)").expect("inline constructor");
        assert!(
            is_declarator_name(&tree, source, inline_declarator, "D"),
            "an inline constructor definition name is still a declarator"
        );

        for (label, start, text) in [
            (
                "base member initializer",
                source.find(": B(x)").expect("base initializer") + ": ".len(),
                "B",
            ),
            (
                "field member initializer",
                source.find("base_(x) {}").expect("field initializer"),
                "base_",
            ),
            (
                "new expression type",
                source.find("new D(1)").expect("new expression") + "new ".len(),
                "D",
            ),
            (
                "direct initialization type",
                source.find("D x(2)").expect("direct initialization"),
                "D",
            ),
            (
                "temporary construction statement",
                source.find("D(3)").expect("temporary"),
                "D",
            ),
            (
                "recursive call in a real body",
                source.find("g();").expect("recursive call"),
                "g",
            ),
        ] {
            assert!(
                !is_declarator_name(&tree, source, start, text),
                "the {label} at byte {start} is a reference"
            );
        }
    }

    /// The recovered shape (#1834): an export macro between `class` and the
    /// class name makes the parse read the class body as a function body and
    /// every constructor declaration in it as a call of the class's own name.
    /// The bodies the recovery left intact keep their references.
    #[test]
    fn a_constructor_declarator_the_parse_read_as_a_call_is_not_a_reference() {
        let source = concat!(
            "class SAMPLE_EXPORT Properties {\n",
            "  public:\n",
            "    Properties();\n",
            "    DISALLOW_COPY_AND_ASSIGN(Properties);\n",
            "    int size() const;\n",
            "    int total() { return size(); }\n",
            "};\n",
        );
        let tree = parse_cpp(source);

        let recovered = source.find("Properties();").expect("recovered constructor");
        assert!(
            is_declarator_name(&tree, source, recovered, "Properties"),
            "a constructor declaration the parse read as a call is still a declarator"
        );

        for (label, start, text) in [
            (
                "class name in the recovered header",
                source
                    .find("class SAMPLE_EXPORT Properties")
                    .expect("class")
                    + "class SAMPLE_EXPORT ".len(),
                "Properties",
            ),
            (
                "macro invocation in the recovered body",
                source
                    .find("DISALLOW_COPY_AND_ASSIGN(Properties);")
                    .expect("macro invocation"),
                "DISALLOW_COPY_AND_ASSIGN",
            ),
            (
                "call inside a method body the recovery kept",
                source.find("return size();").expect("member call") + "return ".len(),
                "size",
            ),
        ] {
            assert!(
                !is_declarator_name(&tree, source, start, text),
                "the {label} at byte {start} stays a reference"
            );
        }
    }
}
