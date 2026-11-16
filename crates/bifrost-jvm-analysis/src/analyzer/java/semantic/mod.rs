//! Java lowering into the language-neutral executable-semantics IR.
//!
//! This module deliberately interprets tree-sitter nodes and fields directly.
//! Graph construction, abrupt-completion routing, cleanup specialization, and
//! physical adjacency storage remain owned by the shared semantic substrate.

use brokk_bifrost_core::analyzer::tree_walk::children_by_field_name;

use brokk_bifrost_semantic::analyzer::semantic::inventory::*;
use brokk_bifrost_semantic::analyzer::semantic::lowering::*;

use tree_sitter::Node;

use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use brokk_bifrost_analysis::analyzer::semantic::cfg::{
    CleanupRegionId, CompletionKind, CompletionRequest, CompletionRoute, ProcedureCfgBuilder,
    ScopeBinding, ScopeFrameId,
};

use brokk_bifrost_semantic::analyzer::semantic::service::ProgramSemanticsLowerer;

use brokk_bifrost_semantic::analyzer::semantic::service::SemanticAdapterIdentity;

use brokk_bifrost_analysis::analyzer::semantic::structural_identity::StructuralNodeIndex;

use brokk_bifrost_analysis::analyzer::semantic::structural_identity::StructuralNodeIndexOutcome;

use brokk_bifrost_analysis::analyzer::semantic::*;

use brokk_bifrost_analysis::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;

use brokk_bifrost_core::analyzer::tree_walk::WalkControl;

use brokk_bifrost_core::analyzer::tree_walk::try_walk_named_tree_preorder;

use crate::analyzer::JavaAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::hash::HashMap;

use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_jvm::java::structural::JAVA_STRUCTURAL_SPEC;

/// The java adapter lever (#11570): `levers/java-adapter.tokens`. Add a line there
/// when a change alters the semantics this lowerer publishes for unchanged
/// source; see `.agents/docs/cache-identity-levers.md`.
fn adapter_version() -> &'static [u8] {
    brokk_bifrost_core::lever_label!("java-value-semantics", "java-adapter.tokens").as_bytes()
}

impl_program_semantics_provider!(JavaAnalyzer, JavaSemanticLowerer);

pub(crate) struct JavaSemanticLowerer;

impl ProgramSemanticsLowerer for JavaSemanticLowerer {
    fn identity(&self) -> SemanticAdapterIdentity {
        SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("java", adapter_version())
                .expect("adapter name is non-empty"),
            configuration: ConfigurationFingerprint::hash_bytes(
                b"java-intrafile-execution-defaults-v1",
            ),
            dependencies:
                brokk_bifrost_analysis::analyzer::semantic::versioned_dependency_fingerprint(
                    b"bifrost.java-semantic.structural-facts-dependency.v1",
                    STRUCTURAL_FACTS_VERSION,
                ),
        }
    }

    fn capabilities(&self) -> SemanticCapabilities {
        java_capabilities()
    }

    fn lower(
        &self,
        file: &ProjectFile,
        prepared: &PreparedSyntaxTree,
        budget: &SemanticBudget,
        cancellation: &CancellationToken,
    ) -> Result<SemanticOutcome<Vec<ProcedureSemanticsParts>>, SemanticProviderError> {
        let (mut specs, mut initial_work, inventory_work) =
            match enumerate_procedures(file, prepared, budget, cancellation)? {
                ProcedureEnumeration::Complete {
                    value,
                    initial_work,
                    inventory_work,
                } => (value, initial_work, inventory_work),
                ProcedureEnumeration::ExceededBudget { exceeded, work } => {
                    return Ok(SemanticOutcome::ExceededBudget {
                        partial: None,
                        exceeded,
                        work,
                    });
                }
                ProcedureEnumeration::Cancelled { work } => {
                    return Ok(SemanticOutcome::Cancelled {
                        partial: None,
                        work,
                    });
                }
                ProcedureEnumeration::Unknown { work } => {
                    return Ok(SemanticOutcome::Unknown {
                        partial: None,
                        work,
                    });
                }
            };
        if relay_receiver_capture_demand(&mut specs, cancellation).is_err() {
            return Ok(SemanticOutcome::Cancelled {
                partial: None,
                work: inventory_work,
            });
        }
        for index in 0..specs.len() {
            if cancellation.is_cancelled() {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: inventory_work,
                });
            }
            let can_capture_receiver = specs[index]
                .lexical_parent
                .and_then(|parent| specs.get(parent.index()))
                .is_some_and(|parent| {
                    parent.captures_receiver
                        || (!parent.properties.is_static
                            && matches!(
                                parent.kind,
                                ProcedureKind::Method
                                    | ProcedureKind::Constructor
                                    | ProcedureKind::Initializer
                            ))
                });
            specs[index].captures_receiver &= can_capture_receiver;
        }
        let procedure_targets = specs
            .iter()
            .map(|spec| {
                (
                    spec.callable.id(),
                    NestedProcedureTarget {
                        id: spec.id,
                        captures: spec.captures.clone(),
                        captures_incomplete: spec.captures_incomplete,
                        receiver_capture_destination: spec
                            .captures_receiver
                            .then_some(RECEIVER_CAPTURE_DESTINATION),
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let remaining = budget
            .limits()
            .nested_entries
            .saturating_sub(inventory_work.nested_entries);
        let structural_node_index = match StructuralNodeIndex::for_source(
            &JAVA_STRUCTURAL_SPEC,
            prepared,
            remaining,
            cancellation,
        )? {
            StructuralNodeIndexOutcome::Complete { index, work_items } => {
                let work = SemanticWork {
                    nested_entries: work_items,
                    ..SemanticWork::default()
                };
                initial_work = initial_work.conservative_add(work);
                index
            }
            StructuralNodeIndexOutcome::Exceeded { minimum_work_items } => {
                let work = inventory_work.conservative_add(SemanticWork {
                    nested_entries: minimum_work_items,
                    ..SemanticWork::default()
                });
                let exceeded = budget
                    .check_admission(work)
                    .expect_err("structural minimum exceeds its remaining semantic budget");
                return Ok(SemanticOutcome::ExceededBudget {
                    partial: None,
                    exceeded,
                    work,
                });
            }
            StructuralNodeIndexOutcome::Cancelled => {
                return Ok(SemanticOutcome::Cancelled {
                    partial: None,
                    work: inventory_work,
                });
            }
        };
        let declaration_inventory = values::java_declaration_inventory(prepared);
        lower_procedure_batch(
            &specs,
            initial_work,
            budget,
            cancellation,
            |spec, staged_budget, cancellation| {
                lower_procedure(
                    prepared,
                    spec,
                    &procedure_targets,
                    &structural_node_index,
                    &declaration_inventory,
                    staged_budget,
                    cancellation,
                )
            },
        )
    }
}

fn java_capabilities() -> SemanticCapabilities {
    brokk_bifrost_analysis::analyzer::semantic::capabilities::tree_sitter_adapter_capabilities()
        .complete(SemanticCapability::SwitchFacts)
        .partial(SemanticCapability::StaticMemory)
        .build()
}

mod control;
mod inventory;
mod numeric;
mod syntax;
pub(crate) use syntax::declaration_container_kind;
#[cfg(test)]
mod tests;
mod values;

use crate::analyzer::java::semantic::control::lower_procedure;

use crate::analyzer::java::semantic::inventory::NestedProcedureTarget;

use crate::analyzer::java::semantic::inventory::ProcedureEnumeration;

use crate::analyzer::java::semantic::inventory::ProcedureSpec;

use crate::analyzer::java::semantic::inventory::enumerate_procedures;

type JavaLoweringError = ProcedureLoweringError;

type EdgeTarget = ControlTarget;

#[derive(Debug, Clone, Copy)]
enum Work<'tree> {
    Statement {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    LabeledStatement {
        node: Node<'tree>,
        label: &'tree str,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    Expression {
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    },
    Condition {
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    },
}

impl<'tree> Work<'tree> {
    const fn statement(
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Statement {
            node,
            entry,
            next,
            scope,
        }
    }

    const fn expression(
        node: Node<'tree>,
        entry: ProgramPointId,
        next: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Expression {
            node,
            entry,
            next,
            scope,
        }
    }

    const fn condition(
        node: Node<'tree>,
        entry: ProgramPointId,
        when_true: EdgeTarget,
        when_false: EdgeTarget,
        scope: ScopeFrameId,
    ) -> Self {
        Self::Condition {
            node,
            entry,
            when_true,
            when_false,
            scope,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CleanupRegion<'tree> {
    id: CleanupRegionId,
    body: CleanupBody<'tree>,
    outer_scope: ScopeFrameId,
}

#[derive(Debug, Clone, Copy)]
enum CleanupBody<'tree> {
    Statement(Node<'tree>),
    OpaqueResource(Node<'tree>),
    OpaqueMonitor(Node<'tree>),
}

impl<'tree> CleanupBody<'tree> {
    const fn source_node(self) -> Node<'tree> {
        match self {
            Self::Statement(node) | Self::OpaqueResource(node) | Self::OpaqueMonitor(node) => node,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JavaSwitchArmKind {
    Group,
    Rule,
}

struct JavaSwitchArm<'tree> {
    node: Node<'tree>,
    labels: Vec<Node<'tree>>,
    body: Vec<Node<'tree>>,
    kind: JavaSwitchArmKind,
}

struct LoweringContext<'tree, 'targets> {
    prepared: &'tree PreparedSyntaxTree,
    structural_node_index: &'targets StructuralNodeIndex,
    session: ProcedureLoweringSession<'targets>,
    return_type: Option<Node<'tree>>,
    expression_values: HashMap<usize, ValueId>,
    constant_index_values: HashMap<Box<str>, ValueId>,
    /// The file's declaration inventory, built once per file by `lower`
    /// and shared read-only by every procedure. Building it walks the whole
    /// file, so a per-procedure build costs procedures x file nodes.
    field_declaration_anchors:
        &'targets HashMap<(usize, Box<str>), Option<values::FieldDeclarationAnchor<'tree>>>,
    source_type_nodes: &'targets HashMap<(usize, Box<str>), Option<Node<'tree>>>,
    type_name_roots: &'targets HashSet<Box<str>>,
    local_types: HashMap<ValueId, Box<str>>,
    local_type_nodes: HashMap<ValueId, Node<'tree>>,
    /// Effectively final `int` and `long` locals whose initializer is an
    /// integer literal, with that value. Such a local holds the value at every
    /// read, so a condition over these locals and literals can be decided at
    /// lowering time (see `LoweringContext::constant_truth`).
    constant_locals: HashMap<ValueId, numeric::JavaNumericLiteral>,
    array_values: HashSet<ValueId>,
    non_null_values: HashSet<ValueId>,
    written_bindings: HashSet<ValueId>,
    catch_binders: HashMap<ProgramPointId, ValueId>,
    /// The value of each switch expression in this procedure, keyed by the
    /// point its `yield` completions end at. A `yield` resolves its
    /// completion route and reads the result it feeds from here.
    yield_results: HashMap<ProgramPointId, ValueId>,
    /// Query-local filter for pattern spellings in this file. The shared
    /// lexical resolver proves each reference; missing value establishments
    /// and record-component extraction keep explicit gaps.
    pattern_variable_names: &'targets HashSet<Box<str>>,
    parameters: HashMap<Box<str>, ValueId>,
    locals: HashMap<Box<str>, Vec<LocalBinding>>,
    /// The per-procedure, per-field-name "virtual local" carrier #2573's
    /// implicit-field mechanism mints lazily; see the `values` submodule's
    /// own `implicit_field_carrier` method for the full doc comment.
    implicit_field_values: HashMap<Box<str>, ValueId>,
    receiver: Option<ValueId>,
    captured_receiver: Option<ValueId>,
    procedure_targets: &'targets HashMap<usize, NestedProcedureTarget<'tree>>,
    cleanups: Vec<CleanupRegion<'tree>>,
}

struct LocalBinding {
    declaration_start: usize,
    visible_from: usize,
    scope_start: usize,
    scope_end: usize,
    value: ValueId,
}

fn java_capture_destination(
    captures_receiver: bool,
    index: usize,
) -> Result<MemoryLocationId, JavaLoweringError> {
    brokk_bifrost_semantic::analyzer::semantic::lowering::lexical_capture_destination(
        captures_receiver,
        index,
        "Java",
    )
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::analyzer::store::semantic_ir::{
        PreparedSemanticIr, SemanticIrLoweringOutcome, SemanticIrMountScope, insert_semantic_ir_tx,
        semantic_ir_producer_epoch,
    };
    use brokk_bifrost_core::analyzer::model::LanguageDialect;
    use brokk_bifrost_core::analyzer::prepared_syntax::{
        PreparedSourceOrigin, PreparedSyntaxSource,
    };
    use brokk_bifrost_core::text_utils::compute_line_starts;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    fn lower_call_control_fixture(source: &str) -> Vec<ProcedureSemanticsParts> {
        let source: Arc<str> = source.into();
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("C.java", source.as_ref())
            .build();
        let file = fixture.file("C.java");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source.as_ref(), None).unwrap();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::clone(&source)),
            tree,
            compute_line_starts(&source),
            LanguageDialect::for_path(Language::Java, file.rel_path()),
            PreparedSourceOrigin::Disk,
            None,
        );
        match JavaSemanticLowerer
            .lower(
                &file,
                &prepared,
                &SemanticBudget::default(),
                &CancellationToken::default(),
            )
            .unwrap()
        {
            SemanticOutcome::Complete { value, .. } => value,
            other => panic!("fixture lowering must complete: {other:?}"),
        }
    }

    #[test]
    #[hardwon("#12650: Java lowering rebuilt the whole-file declaration inventory per procedure")]
    fn declaration_inventory_work_does_not_grow_with_procedure_count() {
        // Each method has an instanceof pattern, so pattern lookups run in
        // every procedure. The inventory walks the whole file, so it is built
        // once per file and its node count follows the file, not the
        // procedure count times the file.
        let mut measured = Vec::new();
        for methods in [200, 400, 800] {
            let mut source = String::from("class C {\n");
            for index in 0..methods {
                source.push_str(&format!(
                    "  int m{index}(Object o) {{ if (o instanceof String s) {{ return s.length(); }} return {index}; }}\n"
                ));
            }
            source.push_str("}\n");
            values::INVENTORY_BUILDS.with(|builds| builds.set(0));
            values::INVENTORY_NODES.with(|nodes| nodes.set(0));
            let parts = lower_call_control_fixture(&source);
            assert_eq!(parts.len(), methods, "one procedure per method");
            let builds = values::INVENTORY_BUILDS.with(|builds| builds.get());
            let nodes = values::INVENTORY_NODES.with(|nodes| nodes.get());
            measured.push((methods, builds, nodes));
        }
        assert!(
            measured.iter().all(|(_, builds, _)| *builds == 1),
            "{measured:?}"
        );
        // Doubling the methods roughly doubles the file's nodes; allow slack
        // for the class declaration and header.
        for pair in measured.windows(2) {
            let (_, _, small) = pair[0];
            let (_, _, large) = pair[1];
            assert!(large <= small * 2 + 10, "{measured:?}");
        }
    }

    #[test]
    #[hardwon("#9550: real Java calls had no adapter admission regression case")]
    fn call_control_real_direct_call_is_admitted() {
        let parts = lower_call_control_fixture(
            "class C { static void f(R x) { g(x); } static void g(R x) {} } class R {}",
        );
        let f = parts
            .iter()
            .find(|p| p.locator.declaration().last_segment_name() == Some("f"))
            .unwrap();
        assert_eq!(
            f.call_control_coverage.admission,
            Ok(()),
            "{:#?}",
            f.call_control_coverage.branches
        );
        assert!(
            f.call_control_coverage
                .branches
                .iter()
                .any(|b| b.kind == CallControlKind::ExplicitCall
                    && b.disposition == CallControlDisposition::Represented)
        );
    }

    #[test]
    #[hardwon("#9550: a parameter annotation call was hidden by signature ownership refusal")]
    fn call_in_parameter_annotation_refuses_scoped_coverage() {
        let source = "@interface A { int value(); } class C { static void f(@A(value = g()) R x) {} static int g() { return 1; } } class R {}";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let parts = lower_call_control_fixture(source);
        let f = parts
            .iter()
            .find(|p| p.locator.declaration().last_segment_name() == Some("f"))
            .unwrap();
        let parameter =
            brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
                tree.root_node(),
                "formal_parameter",
            )
            .unwrap();
        let call =
            brokk_bifrost_core::analyzer::tree_walk::first_named_descendant_of_kind_inclusive(
                parameter,
                "method_invocation",
            )
            .unwrap();
        assert!(
            call.start_byte() >= parameter.start_byte() && call.end_byte() <= parameter.end_byte()
        );
        assert!(f.call_control_coverage.admission.is_err());
    }

    #[test]
    #[hardwon("#7369: Java pattern captures and compound writes must retain their row provenance")]
    fn java_pattern_capture_and_static_write_rows_survive_epoch_miss_and_reopen() {
        // Java does not register a production parse-time IR writer. Publish
        // real lowering output explicitly to exercise the existing SQL codec
        // without activating a new product producer as a side effect of a fix.
        let source: Arc<str> = r#"class C {
            interface Supplier { Object get(); }
            static int count;
            static Supplier make(Object obj, int n) {
                count >>= n;
                if (obj instanceof C other) return () -> other;
                return () -> null;
            }
        }"#
        .into();
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("C.java", source.as_ref())
            .build();
        let file = fixture.file("C.java");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source.as_ref(), None).unwrap();
        let prepared = PreparedSyntaxTree::new(
            PreparedSyntaxSource::Exact(Arc::clone(&source)),
            tree,
            compute_line_starts(&source),
            LanguageDialect::for_path(Language::Java, file.rel_path()),
            PreparedSourceOrigin::Disk,
            None,
        );
        let lowerer = JavaSemanticLowerer;
        let cancellation = CancellationToken::default();
        let parts = match lowerer
            .lower(&file, &prepared, &SemanticBudget::default(), &cancellation)
            .unwrap()
        {
            SemanticOutcome::Complete { value, .. } => value,
            other => panic!("fixture lowering must complete: {other:?}"),
        };
        let identity = lowerer.identity();
        let content = ContentIdentity::hash_bytes(source.as_bytes());
        let key = brokk_bifrost_semantic::analyzer::semantic::service::semantic_artifact_key_from_content(
            &file, prepared.dialect(), content, None, identity.clone(),
        ).unwrap();
        let cold =
            SemanticArtifact::try_new(key.clone(), lowerer.capabilities(), parts.clone()).unwrap();
        assert!(
            cold.procedures()
                .iter()
                .any(|procedure| !procedure.captures().is_empty()),
            "real pattern capture must run"
        );
        assert!(
            cold.procedures()
                .iter()
                .flat_map(|procedure| procedure.points())
                .flat_map(|point| &point.events)
                .any(|event| matches!(
                    event.effect,
                    SemanticEffect::MemoryStore {
                        kind: MemoryAccessKind::Static,
                        ..
                    }
                )),
            "real compound static write must run"
        );
        let database = fixture.root().join("semantic-rows.sqlite");
        let epoch = semantic_ir_producer_epoch(&identity);
        let rows = PreparedSemanticIr::prepare(
            SemanticIrLoweringOutcome::Complete { parts },
            None,
            &epoch,
            content,
            source.len(),
        );
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        store
            .ensure_semantic_ir_producer_epoch("java", &epoch)
            .unwrap();
        let blob_id = store.conn.execute(move |conn| {
            conn.execute(
                "INSERT INTO blobs(blob_oid, lang, generation) VALUES(?1, 'java', 1)",
                [oid.to_string()],
            )
            .unwrap();
            let blob_id = conn.last_insert_rowid();
            let tx = conn.transaction().unwrap();
            assert!(insert_semantic_ir_tx(&tx, blob_id, "java", &rows, &cancellation).unwrap());
            tx.commit().unwrap();
            blob_id
        });
        assert!(
            store
                .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    oid, "java"
                ))
                .unwrap()
                .is_some()
        );
        drop(store);
        let old = SemanticAdapterIdentity {
            adapter: AdapterSemanticsVersion::hash_bytes("java", b"java-value-semantics-v30")
                .unwrap(),
            ..identity
        };
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE semantic_ir_publications SET producer_epoch = ?1 WHERE blob_id = ?2",
                    rusqlite::params![semantic_ir_producer_epoch(&old), blob_id]
                )
                .unwrap(),
            1
        );
        drop(connection);
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        assert!(
            store
                .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                    oid, "java"
                ))
                .unwrap()
                .is_none(),
            "old adapter publication must miss under current producer"
        );
        drop(store);
        // Simulate republishing identical source under the current producer,
        // then decode from a fresh store instance as a consumer would.
        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .execute(
                    "UPDATE semantic_ir_publications SET producer_epoch = ?1 WHERE blob_id = ?2",
                    rusqlite::params![epoch, blob_id]
                )
                .unwrap(),
            1
        );
        drop(connection);
        let store = AnalyzerStore::open_persistent(&database).unwrap();
        let publication = store
            .semantic_ir_publication(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "java"))
            .unwrap()
            .expect("current publication");
        let scope =
            SemanticIrMountScope::new(key.mount(), key.path().clone(), key.language(), content);
        let replay = SemanticArtifact::try_new(
            key,
            lowerer.capabilities(),
            store.read_semantic_ir(publication.blob_id, &scope).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cold.materialization_id(),
            replay.materialization_id(),
            "all capture, value, write, guard and evidence rows must survive the codec and remount"
        );
        assert_eq!(cold.work(), replay.work());
    }
}
