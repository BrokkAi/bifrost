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
//! * The moka cell that memoizes [`cpp_reconciled_definitions`] per queried name
//!   stays on the analyzer, as does every other cache, so `IAnalyzer::update`
//!   keeps rebuilding them wholesale.

use crate::declarations::{cpp_file_using_namespaces, cpp_member_fq};
use crate::graph_support::CppAnalysisSource;
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

/// Reconcile the bounded candidate set for one queried canonical `fq_name`:
/// every out-of-line member definition sharing its terminal identifier whose
/// provisional per-file identity the include-visible class table re-keys onto
/// exactly this name (the two ambiguous shapes left by #1121). A definition
/// whose reconciled identity equals its provisional one (the overwhelming
/// majority, including genuine `ns1::ns2::Klass::method` namespace chains)
/// contributes nothing.
///
/// Deliberately **not** a workspace-wide index: building one would need a full
/// declaration scan, and a warm forward lookup must not trigger one
/// (`tests/analyzer_persistence.rs`'s candidate-bounded contract). Instead each
/// queried name reconciles only the candidates the persisted terminal identifier
/// index already offers, which is the same bounded lookup the ordinary
/// resolution path uses.
pub fn cpp_reconciled_definitions(
    cpp: &dyn CppAnalysisSource,
    fq_name: &str,
) -> CppReconciledDefinitionIndex {
    let _scope = profiling::scope(format!("cpp.reconciled.build[{fq_name}]"));
    let mut index = CppReconciledDefinitionIndex::default();
    let interner = segment_interner();
    // The queried name's terminal segment is the member identifier to probe
    // the identifier index with. Parsed through the sanctioned input-edge
    // parser rather than split here, and note `$` is not a segment boundary
    // for it -- a nested owner chain stays one segment, so the terminal
    // really is the member.
    let query_fq = parse_symbol_path_fq(Language::Cpp, fq_name, interner);
    let Some(member_segment) = query_fq.last() else {
        return index;
    };
    let (member_identifier, _) = interner.resolve(member_segment);
    if member_identifier.is_empty() {
        return index;
    }

    // #1566 owner-terminal pre-filter: the reconciler only re-partitions a
    // candidate's qualifier -- the class chain it emits is always a suffix
    // of the candidate's owner segments (`reconcile.rs`) -- so the terminal
    // `$` component of any identity it can produce equals the candidate's
    // terminal owner segment. A candidate whose terminal owner differs
    // from the queried name's penultimate segment can therefore never
    // re-key onto it, and skipping it here avoids the role check and, on
    // whale repos, an include-closure class-table build per same-named
    // candidate in the repo (chromium paid ~75s per member query that way:
    // one BFS per same-named candidate file, 2.5M declaration queries per
    // probe file for a gtest-shaped member name).
    let query_owner_terminal = query_fq.segments().len().checked_sub(2).map(|penultimate| {
        let (text, _) = interner.resolve(query_fq.segments()[penultimate]);
        // fqname-M4: the input-edge parser above deliberately keeps a nested
        // owner chain as one `$`-joined segment (no structured sub-segments
        // exist at this surface), so the terminal component must come from
        // the raw text.
        text.rsplit_once('$').map_or(text, |(_, tail)| tail)
    });

    let mut using_by_file: HashMap<ProjectFile, Arc<Vec<String>>> = HashMap::default();
    let candidates: BTreeSet<CodeUnit> = {
        let _lookup = profiling::scope(format!("cpp.reconcile.lookup[{member_identifier}]"));
        cpp.lookup_candidates_by_identifier(member_identifier)
    };
    profiling::note(format!(
        "cpp.reconcile.candidates[{member_identifier}] n={}",
        candidates.len()
    ));
    for unit in candidates {
        let _candidate = profiling::scope(format!("cpp.reconcile.candidate[{}]", unit.fq_name()));
        let candidate_owner_terminal = unit
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
        if let Some(query_terminal) = query_owner_terminal
            && candidate_owner_terminal != Some(query_terminal)
        {
            continue;
        }
        if !unit.is_callable() || unit.fq_name() == fq_name {
            continue;
        }
        let role = {
            let _role = profiling::scope("cpp.reconcile.role");
            cpp_callable_unit_role(cpp, &unit)
        };
        if !matches!(
            role,
            CppCallableUnitRole::Definition | CppCallableUnitRole::Both
        ) {
            continue;
        }
        let Some(reconciled) = cpp_reconcile_definition_identity(cpp, &unit, &mut using_by_file)
        else {
            continue;
        };
        let canonical_fq = reconciled.fq_name();
        if canonical_fq != fq_name {
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
        index.rekeyed.push(rekeyed.clone());
        index.provisional_of.insert(rekeyed, unit);
    }
    index
}

/// Reconcile one out-of-line member definition's provisional identity against
/// the class table visible to its file. Returns `None` for anything that is
/// not a re-keyable out-of-line member (free functions with no owner, single
/// segment qualifiers) or that the class table does not confirm.
fn cpp_reconcile_definition_identity(
    cpp: &dyn CppAnalysisSource,
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
    let mut owner_segments: Vec<&str> = Vec::new();
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
                    owner_segments.push(text);
                }
            }
            SegmentKind::Member => member = Some(text),
            _ => return None,
        }
    }
    let member = member?;
    if owner_segments.len() < 2 {
        return None;
    }

    let using = using_by_file
        .entry(unit.source().clone())
        .or_insert_with(|| {
            Arc::new(
                cpp.cpp_file_source(unit.source())
                    .map(|source| cpp_file_using_namespaces(&source))
                    .unwrap_or_default(),
            )
        })
        .clone();
    let mut namespace_candidates: Vec<&str> = vec![""];
    namespace_candidates.extend(using.iter().map(String::as_str));

    let visible = {
        let _visible = profiling::scope(format!(
            "cpp.reconcile.visible[{}]",
            rel_path_string(unit.source())
        ));
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
