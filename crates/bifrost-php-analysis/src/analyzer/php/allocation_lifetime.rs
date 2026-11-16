//! Query-time proof that releasing a `new` allocation runs no user code
//! (#11428).
//!
//! PHP lowering is per file. It omits an allocation's destructor-timing gap
//! only for a class the lowered file states in full (the release rule beside
//! `php_class_facts` in the semantic module). `new UploadedFile()` with
//! `UploadedFile` declared in another workspace file, or in a vendor tree,
//! therefore keeps an `Unknown` `ResourceManagement` gap, and the gap makes
//! the whole procedure's taint inconclusive even when the allocated object
//! never reaches the flow.
//!
//! At query time the workspace has the declaration. This module retires the
//! gap of one exact allocation when releasing the allocated object provably
//! runs no user code:
//!
//! - The `new` names one class, and the class resolves to exactly one source
//!   declaration. A class only a semantic model declares, `new static`, a
//!   dynamic class name and an anonymous class all keep the gap.
//! - That class, every class it `extends`, every trait it uses, and every
//!   class or enum that one of their typed properties holds resolves to
//!   exactly one source declaration, and none of them declares `__destruct`.
//!   PHP method names are case-insensitive, so `__DESTRUCT` counts.
//! - No property is untyped or typed so that it may hold an object that
//!   cannot be followed (a nullable object, a union, an array, `object`,
//!   `mixed`, ...), and no trait use adapts trait methods, because an
//!   adaptation can alias a trait method as `__destruct`. A property typed as
//!   a class holds an instance of any subclass of it, so the class must be
//!   `final`; an enum admits neither a subclass nor a `__destruct`.
//!
//! The answer is the greatest fixpoint, as in the per-file rule: a cycle of
//! clean classes closes. Interfaces are not followed, because an interface
//! states no method body and so cannot contribute a destructor. `new self()`,
//! `new parent()` and `new static()` name their class relative to the
//! enclosing scope; lowering never closes such a creation, so the proof keeps
//! those gaps too rather than answer a question lowering never asked.
//!
//! Every declaration the proof reads is charged to the request budget. A
//! refusal keeps the gap, and the recorded stop keeps the partial answer out
//! of every fill that would store it as finished.
//!
//! Every fact comes through a funnel that records its read: the constructor's
//! type lookup, `definitions` for each resolved name (its answer digest
//! covers the whole declaration set, so a second declaration or a deletion
//! moves it), and the indexed syntax of each declaring file. A kept answer for
//! the caller's file therefore misses when any declaration it consulted
//! changes, for example when the class gains a `__destruct`.

use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::semantic::type_flow::file_for_locator;
use brokk_bifrost_analysis::analyzer::semantic::{
    AllocationKind, ProcedureHandle, SemanticCapability, SemanticGapDischarge, SemanticGapId,
    SemanticGapKind, SemanticGapSubject, SemanticRequest, SemanticWork, ValueId,
};
use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::common::try_node_source_text as node_text;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_core::analyzer::tree_walk::{is_comment_kind, named_children_vec};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_php::aliases::{PhpFileContextIndex, resolve_php_type_node};
use brokk_bifrost_php::graph::syntax::object_creation_type;
use brokk_bifrost_semantic::analyzer::semantic::type_flow::{
    ClassIdentity, ClassSeed, node_at_span,
};
use tree_sitter::Node;

use super::PhpAnalyzer;
use super::semantic::{PhpPropertyRelease, php_property_release};
use super::type_flow::{
    current_indexed_prepared, declaration_node, prepared_for_procedure, resolve_constructor,
};

/// The most class-like declarations one release proof reads. A closure
/// larger than this keeps its gap. This cap is a second bound: each
/// declaration read is charged to the request budget, so a proof the budget
/// refuses stops earlier and also keeps the gap. Within one budget the same
/// workspace always gets the same answer.
const PHP_MAX_RELEASE_DECLARATIONS: usize = 128;

/// The resource-lifetime gaps of `procedure` whose allocation releases
/// without running user code. A cancelled proof retires only the gaps it
/// finished proving, and a proof the request budget refuses retires none of
/// the allocations it never finished: both stops are recorded on the request,
/// so no consumer can store the partial answer as a finished one.
pub(crate) fn resolved_allocation_lifetime_gaps(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
    request: &mut SemanticRequest<'_>,
) -> Vec<SemanticGapId> {
    let semantics = procedure.semantics();
    let candidates = semantics
        .gaps()
        .iter()
        .filter(|gap| {
            gap.capability == SemanticCapability::ResourceManagement
                && matches!(gap.subject, SemanticGapSubject::Point)
                && gap.kind == SemanticGapKind::Unknown
                && gap.discharge == SemanticGapDischarge::None
        })
        .filter_map(|gap| Some((gap.id, allocated_result(procedure, gap.point)?)))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Vec::new();
    }
    let Some(php) = super::resolve_php_analyzer(workspace) else {
        return Vec::new();
    };
    let Some(file) = file_for_locator(workspace, semantics.locator()) else {
        return Vec::new();
    };
    // The exact tree the procedure was lowered from, so the result value's
    // span addresses the allocation's own syntax.
    let Ok(prepared) = prepared_for_procedure(workspace, procedure, &file) else {
        return Vec::new();
    };
    let mut proof = ReleaseProof::new(php);
    let mut retired = Vec::new();
    for (gap, result) in candidates {
        // A recorded budget stop ends the proof: without it every remaining
        // allocation could still load its declaring files before the next
        // admission refuses, so the budget would not bound the query.
        if request.cancellation.is_cancelled() || proof.budget_stopped {
            break;
        }
        let value = semantics
            .value(result)
            .expect("an allocation result belongs to its procedure");
        let mapping = semantics
            .source_mapping(value.source)
            .expect("an allocation result has a source mapping");
        let Some(creation) = node_at_span(&prepared, mapping.locator.anchor().span())
            .filter(|node| node.kind() == "object_creation_expression")
        else {
            continue;
        };
        // `new self()`, `new parent()` and `new static()` name their class
        // relative to the enclosing scope; the grammar parses the designator
        // as a plain `name`. Lowering never closes such a creation (the file's
        // class inventory holds no `self` or `parent` class), so this proof
        // keeps the gap as well rather than retire a gap lowering deliberately
        // recorded.
        if object_creation_type(creation)
            .and_then(|class| node_text(class, prepared.source()))
            .is_some_and(|name| {
                ["self", "parent", "static"]
                    .iter()
                    .any(|scope| name.eq_ignore_ascii_case(scope))
            })
        {
            continue;
        }
        let ClassSeed::Class(ClassIdentity::Workspace(class)) =
            resolve_constructor(workspace, procedure, &file, &prepared, creation)
        else {
            continue;
        };
        if proof.releases_without_user_code(class, request) {
            retired.push(gap);
        }
    }
    retired
}

/// The result of the call at `point` when an object allocation produces it.
fn allocated_result(
    procedure: &ProcedureHandle,
    point: brokk_bifrost_analysis::analyzer::semantic::ProgramPointId,
) -> Option<ValueId> {
    let semantics = procedure.semantics();
    let result = semantics
        .call_sites()
        .iter()
        .find(|call| call.point == point)?
        .result?;
    semantics
        .allocations()
        .iter()
        .any(|allocation| allocation.result == result && allocation.kind == AllocationKind::Object)
        .then_some(result)
}

/// The declaration kinds a name in each position may resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ReleaseRole {
    /// The allocated class, or a class an `extends` clause names.
    Class,
    /// A trait a `use` inside a class body names.
    Trait,
    /// What a typed property holds. An enum case is a singleton that is never
    /// released, and PHP rejects `__destruct` in an enum. A class must be
    /// `final`: a property typed as a class holds an instance of any subclass
    /// of it, and the subclass may declare `__destruct`.
    Held,
}

impl ReleaseRole {
    fn admits(self, kind: &str) -> bool {
        match self {
            Self::Class => kind == "class_declaration",
            Self::Trait => kind == "trait_declaration",
            Self::Held => matches!(kind, "class_declaration" | "enum_declaration"),
        }
    }
}

/// One procedure's release proofs. Answers and declaring-file syntax are
/// shared across the allocations of that procedure.
struct ReleaseProof<'a> {
    php: &'a PhpAnalyzer,
    answers: HashMap<CodeUnit, bool>,
    files: HashMap<ProjectFile, Option<DeclaringFile>>,
    /// The request budget refused a read. Once set, the proof reads nothing
    /// more: the stop bounds the query and every unproven allocation keeps
    /// its gap.
    budget_stopped: bool,
}

/// The current indexed syntax of one declaring file and its namespace
/// contexts.
#[derive(Clone)]
struct DeclaringFile {
    prepared: Arc<PreparedSyntaxTree>,
    contexts: Arc<PhpFileContextIndex>,
}

impl<'a> ReleaseProof<'a> {
    fn new(php: &'a PhpAnalyzer) -> Self {
        Self {
            php,
            answers: HashMap::default(),
            files: HashMap::default(),
            budget_stopped: false,
        }
    }

    /// Charge `work` to the request budget, remembering a refusal so the
    /// proof reads nothing more.
    fn admit(&mut self, request: &mut SemanticRequest<'_>, work: SemanticWork) -> Option<()> {
        if request.budget.admit(work).is_err() {
            self.budget_stopped = true;
            return None;
        }
        Some(())
    }

    /// Whether releasing an instance of `class` runs no user code.
    fn releases_without_user_code(
        &mut self,
        class: CodeUnit,
        request: &mut SemanticRequest<'_>,
    ) -> bool {
        if let Some(answer) = self.answers.get(&class) {
            return *answer;
        }
        let answer = self.closure_is_clean(class.clone(), request);
        self.answers.insert(class, answer);
        answer
    }

    /// Visit every declaration the release of `root` depends on. The closure
    /// is clean when every one of them resolves and runs nothing on release.
    /// A declaration already visited *in the same role* is not visited again,
    /// which is what closes a cycle; the role is part of the key because the
    /// `Held` role alone requires a `final` class, and a class first visited
    /// as the allocated class must still face that check when a property
    /// holds it.
    fn closure_is_clean(&mut self, root: CodeUnit, request: &mut SemanticRequest<'_>) -> bool {
        let mut visited = HashSet::default();
        let mut pending = vec![(root, ReleaseRole::Class)];
        while let Some((unit, role)) = pending.pop() {
            if !visited.insert((unit.clone(), role)) {
                continue;
            }
            if visited.len() > PHP_MAX_RELEASE_DECLARATIONS || request.cancellation.is_cancelled() {
                return false;
            }
            let Some(dependencies) = self.release_dependencies(&unit, role, request) else {
                return false;
            };
            pending.extend(dependencies);
        }
        true
    }

    /// The declarations releasing an instance of `unit` also depends on, or
    /// `None` when its own declaration may run user code on release or names
    /// something that does not resolve to exactly one source declaration.
    fn release_dependencies(
        &mut self,
        unit: &CodeUnit,
        role: ReleaseRole,
        request: &mut SemanticRequest<'_>,
    ) -> Option<Vec<(CodeUnit, ReleaseRole)>> {
        // One source declaration: a class stated twice, for example under a
        // `class_exists` guard, may be either one at run time.
        if self.php.ranges(unit).len() != 1 {
            return None;
        }
        let DeclaringFile { prepared, contexts } = self.file(unit.source(), request)?;
        let declaration = declaration_node(self.php, &prepared, unit)?;
        // The proof reads this declaration's full text. Charge the read to
        // the request budget before inspecting anything the declaration
        // states; a refusal is a budget stop, and a stopped proof keeps the
        // gap.
        self.admit(
            request,
            SemanticWork {
                source_bytes: declaration
                    .end_byte()
                    .saturating_sub(declaration.start_byte()),
                ..SemanticWork::default()
            },
        )?;
        if !role.admits(declaration.kind()) {
            return None;
        }
        // A property typed as a class holds an instance of any subclass of
        // it, and the subclass may declare `__destruct`; only a `final`
        // class bounds what the property holds. An enum needs no modifier.
        if role == ReleaseRole::Held
            && declaration.kind() == "class_declaration"
            && !named_children_vec(declaration)
                .iter()
                .any(|child| child.kind() == "final_modifier")
        {
            return None;
        }
        let source = prepared.source();
        let edges = php_release_edges(source, declaration)?;
        let mut dependencies = Vec::new();
        for (name, role) in edges {
            let context = contexts.context_at(name.start_byte());
            let fqn = resolve_php_type_node(name, source, context, || true)?;
            dependencies.push((self.unique_declaration(&fqn)?, role));
        }
        Some(dependencies)
    }

    /// The one class-like source declaration `fqn` names.
    fn unique_declaration(&self, fqn: &str) -> Option<CodeUnit> {
        let mut units = self
            .php
            .definitions(fqn)
            .filter(CodeUnit::is_class)
            .collect::<Vec<_>>();
        units.sort();
        units.dedup();
        match units.as_slice() {
            [unit] => Some(unit.clone()),
            _ => None,
        }
    }

    /// The current indexed syntax of a declaring file and its namespace
    /// contexts, read once per proof. Loading the file charges its source
    /// bytes to the request budget; a refusal is a budget stop and the proof
    /// keeps the gap.
    fn file(
        &mut self,
        file: &ProjectFile,
        request: &mut SemanticRequest<'_>,
    ) -> Option<DeclaringFile> {
        if let Some(cached) = self.files.get(file) {
            return cached.clone();
        }
        let loaded = match current_indexed_prepared(self.php, file) {
            Some(prepared) => match self.admit(
                request,
                SemanticWork {
                    source_bytes: prepared.source().len(),
                    ..SemanticWork::default()
                },
            ) {
                Some(()) => PhpFileContextIndex::from_tree(
                    prepared.tree().root_node(),
                    prepared.source(),
                    || true,
                )
                .map(|contexts| DeclaringFile {
                    prepared,
                    contexts: Arc::new(contexts),
                }),
                None => None,
            },
            None => None,
        };
        self.files.insert(file.clone(), loaded.clone());
        loaded
    }
}

/// The names one class-like declaration's release depends on, each with the
/// role its declaration must have, or `None` when releasing an instance may
/// run code this declaration states or that cannot be followed.
///
/// The `extends` clause names the parent, whose release code runs for this
/// class too. A trait use copies the trait's methods and properties into the
/// class. A typed property names what it may hold. The `implements` clause is
/// not followed: an interface states no method body.
fn php_release_edges<'tree>(
    source: &str,
    declaration: Node<'tree>,
) -> Option<Vec<(Node<'tree>, ReleaseRole)>> {
    if declaration.has_error() {
        return None;
    }
    let mut edges = Vec::new();
    for clause in named_children_vec(declaration) {
        if clause.kind() == "base_clause" {
            for parent in named_children_vec(clause) {
                push_name(&mut edges, parent, ReleaseRole::Class)?;
            }
        }
    }
    // A declaration whose body this adapter cannot read states nothing it can
    // rely on.
    let body = declaration.child_by_field_name("body")?;
    for member in named_children_vec(body) {
        match member.kind() {
            "use_declaration" => {
                for used in named_children_vec(member) {
                    // `use T { cleanup as __destruct; }` makes a trait method
                    // this class's destructor, so no adaptation is followed.
                    if used.kind() == "use_list" {
                        return None;
                    }
                    push_name(&mut edges, used, ReleaseRole::Trait)?;
                }
            }
            "property_declaration" => {
                push_held(&mut edges, source, member.child_by_field_name("type"))?;
            }
            "method_declaration" => {
                let name = member
                    .child_by_field_name("name")
                    .and_then(|name| node_text(name, source))?;
                if name.eq_ignore_ascii_case("__destruct") {
                    return None;
                }
                // Constructor property promotion declares properties in the
                // parameter list rather than in the class body.
                for parameter in member
                    .child_by_field_name("parameters")
                    .map(named_children_vec)
                    .unwrap_or_default()
                {
                    if parameter.kind() == "property_promotion_parameter" {
                        push_held(&mut edges, source, parameter.child_by_field_name("type"))?;
                    }
                }
            }
            _ => {}
        }
    }
    Some(edges)
}

/// Record a class or trait name, skipping comments. Any other node is syntax
/// this proof does not follow.
fn push_name<'tree>(
    edges: &mut Vec<(Node<'tree>, ReleaseRole)>,
    node: Node<'tree>,
    role: ReleaseRole,
) -> Option<()> {
    match node.kind() {
        "name" | "qualified_name" | "relative_name" | "fully_qualified_name" => {
            edges.push((node, role))
        }
        kind if is_comment_kind(kind) => {}
        _ => return None,
    }
    Some(())
}

/// Record what one property's declared type may hold.
fn push_held<'tree>(
    edges: &mut Vec<(Node<'tree>, ReleaseRole)>,
    source: &str,
    type_node: Option<Node<'tree>>,
) -> Option<()> {
    match php_property_release(source, type_node) {
        PhpPropertyRelease::NoObject => {}
        PhpPropertyRelease::Class(held) => edges.push((held, ReleaseRole::Held)),
        PhpPropertyRelease::Unfollowable => return None,
    }
    Some(())
}
