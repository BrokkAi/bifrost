mod common;

use std::sync::Arc;

use brokk_bifrost::analyzer::WorkspaceAnalyzer;
use brokk_bifrost::analyzer::semantic::ProcedureHandle;
use brokk_bifrost::analyzer::structural::{
    ProtocolRef, ProtocolRegistration, ProtocolRegistrationLimits, ProtocolRegistrationOutcome,
    ProtocolRegistrationSet, ProtocolRegistrationSetError, QueryAnalysisContext,
    QueryAnalysisContextError, QueryAnalysisValidationLimits,
};
use brokk_bifrost::analyzer::typestate::{CompiledProtocol, ProtocolSpec, TypestateBindingPlan};
use brokk_bifrost::{AnalyzerConfig, CancellationToken, Language};

use common::semantic_graph::{PointSelector, resolve_procedure_handle};
use common::{BuiltInlineTestProject, InlineTestProject};

const RESOURCE_LIFECYCLE: &[u8] =
    include_bytes!("fixtures/typestate/resource-lifecycle.protocol.json");
const SOURCE: &str = r#"
export function lifecycle() {
  return 1;
}
"#;

struct Fixture {
    project: BuiltInlineTestProject,
    analyzer: WorkspaceAnalyzer,
    root: ProcedureHandle,
    protocol: Arc<CompiledProtocol>,
    bindings: Arc<TypestateBindingPlan>,
}

impl Fixture {
    fn new() -> Self {
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("src/main.ts", SOURCE)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let root = resolve_procedure_handle(
            &project,
            &analyzer,
            "src/main.ts",
            PointSelector::new("function lifecycle")
                .procedure("lifecycle")
                .effect("entry"),
        );
        let protocol = Arc::new(
            ProtocolSpec::from_json(RESOURCE_LIFECYCLE)
                .expect("fixture protocol parses")
                .compile()
                .expect("fixture protocol compiles"),
        );
        let bindings = Arc::new(
            TypestateBindingPlan::try_new(&protocol, vec![], vec![], vec![], vec![])
                .expect("empty fixture binding plan compiles"),
        );
        Self {
            project,
            analyzer,
            root,
            protocol,
            bindings,
        }
    }

    fn registration(&self, workspace_generation: u64) -> ProtocolRegistration {
        ProtocolRegistration::new(
            workspace_generation,
            self.root.clone(),
            Arc::clone(&self.protocol),
            Arc::clone(&self.bindings),
        )
        .expect("fixture registration is internally consistent")
    }
}

#[test]
fn protocol_refs_are_bounded_namespaced_wire_values() {
    let protocol_ref: ProtocolRef = "embedding:bifrost.test.resource-lifecycle"
        .parse()
        .expect("valid protocol ref");
    assert_eq!(protocol_ref.namespace(), "embedding");
    assert_eq!(protocol_ref.name(), "bifrost.test.resource-lifecycle");
    assert_eq!(
        serde_json::to_string(&protocol_ref).unwrap(),
        r#""embedding:bifrost.test.resource-lifecycle""#
    );
    assert_eq!(
        serde_json::from_str::<ProtocolRef>(r#""embedding:bifrost.test.resource-lifecycle""#)
            .unwrap(),
        protocol_ref
    );
    assert!(
        "missing-namespace-separator"
            .parse::<ProtocolRef>()
            .is_err()
    );
    assert!("Embedding:resource".parse::<ProtocolRef>().is_err());
    assert!("embedding:resource:extra".parse::<ProtocolRef>().is_err());
}

#[test]
fn registration_is_transactional_idempotent_and_deduplicates_aliases() {
    let fixture = Fixture::new();
    let primary: ProtocolRef = "test:primary".parse().unwrap();
    let alias: ProtocolRef = "test:alias".parse().unwrap();
    let mut registrations = ProtocolRegistrationSet::default();

    assert_eq!(
        registrations
            .register(primary.clone(), fixture.registration(7))
            .unwrap(),
        ProtocolRegistrationOutcome::Inserted
    );
    assert_eq!(
        registrations
            .register(primary.clone(), fixture.registration(7))
            .unwrap(),
        ProtocolRegistrationOutcome::Unchanged
    );
    assert_eq!(
        registrations
            .register(alias.clone(), fixture.registration(7))
            .unwrap(),
        ProtocolRegistrationOutcome::Aliased
    );
    assert_eq!(registrations.reference_count(), 2);
    assert_eq!(registrations.registration_count(), 1);
    assert!(Arc::ptr_eq(
        registrations.get(&primary).unwrap(),
        registrations.get(&alias).unwrap()
    ));

    let protocol_bytes = registrations.retained_protocol_bytes();
    let binding_bytes = registrations.retained_binding_plan_bytes();
    assert!(registrations.unregister(&primary));
    assert_eq!(registrations.reference_count(), 1);
    assert_eq!(registrations.registration_count(), 1);
    assert_eq!(registrations.retained_protocol_bytes(), protocol_bytes);
    assert_eq!(registrations.retained_binding_plan_bytes(), binding_bytes);
    assert!(!registrations.unregister(&primary));
    assert!(registrations.unregister(&alias));
    assert_eq!(registrations.reference_count(), 0);
    assert_eq!(registrations.registration_count(), 0);
    assert_eq!(registrations.retained_protocol_bytes(), 0);
    assert_eq!(registrations.retained_binding_plan_bytes(), 0);

    registrations
        .register(primary.clone(), fixture.registration(7))
        .unwrap();
    registrations
        .register(alias.clone(), fixture.registration(7))
        .unwrap();

    let error = registrations
        .register(primary.clone(), fixture.registration(8))
        .expect_err("same reference cannot silently change registrations");
    assert_eq!(
        error,
        ProtocolRegistrationSetError::ReferenceConflict {
            protocol_ref: primary
        }
    );
    assert_eq!(registrations.reference_count(), 2);
    assert_eq!(registrations.registration_count(), 1);
}

#[test]
fn registration_limits_are_independent_and_fail_before_mutation() {
    let fixture = Fixture::new();
    let primary: ProtocolRef = "test:primary".parse().unwrap();
    let alias: ProtocolRef = "test:alias".parse().unwrap();
    let protocol_bytes = fixture.protocol.canonical_bytes().len();
    let binding_bytes = fixture.bindings.canonical_bytes().len();

    let mut references = ProtocolRegistrationSet::with_limits(ProtocolRegistrationLimits::bounded(
        1,
        2,
        protocol_bytes * 2,
        binding_bytes * 2,
    ));
    references
        .register(primary.clone(), fixture.registration(1))
        .unwrap();
    assert_eq!(
        references
            .register(alias.clone(), fixture.registration(1))
            .unwrap_err(),
        ProtocolRegistrationSetError::TooManyReferences { maximum: 1 }
    );
    assert_eq!(references.reference_count(), 1);
    assert_eq!(references.registration_count(), 1);

    let mut unique = ProtocolRegistrationSet::with_limits(ProtocolRegistrationLimits::bounded(
        2,
        1,
        protocol_bytes * 2,
        binding_bytes * 2,
    ));
    unique
        .register(primary.clone(), fixture.registration(1))
        .unwrap();
    assert_eq!(
        unique
            .register(alias.clone(), fixture.registration(2))
            .unwrap_err(),
        ProtocolRegistrationSetError::TooManyRegistrations { maximum: 1 }
    );
    assert_eq!(unique.reference_count(), 1);
    assert_eq!(unique.registration_count(), 1);

    let mut protocols = ProtocolRegistrationSet::with_limits(ProtocolRegistrationLimits::bounded(
        1,
        1,
        protocol_bytes - 1,
        binding_bytes,
    ));
    assert_eq!(
        protocols
            .register(primary.clone(), fixture.registration(1))
            .unwrap_err(),
        ProtocolRegistrationSetError::RetainedProtocolBytes {
            maximum: protocol_bytes - 1
        }
    );
    assert_eq!(protocols.reference_count(), 0);
    assert_eq!(protocols.registration_count(), 0);

    let mut bindings = ProtocolRegistrationSet::with_limits(ProtocolRegistrationLimits::bounded(
        1,
        1,
        protocol_bytes,
        binding_bytes - 1,
    ));
    assert_eq!(
        bindings
            .register(primary, fixture.registration(1))
            .unwrap_err(),
        ProtocolRegistrationSetError::RetainedBindingPlanBytes {
            maximum: binding_bytes - 1
        }
    );
    assert_eq!(bindings.reference_count(), 0);
    assert_eq!(bindings.registration_count(), 0);

    let registration = fixture.registration(1);
    let artifact_bytes = registration.retained_artifact_bytes();
    let mut artifacts = ProtocolRegistrationSet::with_limits(
        ProtocolRegistrationLimits::bounded_with_artifact_bytes(
            1,
            1,
            protocol_bytes,
            binding_bytes,
            artifact_bytes - 1,
        ),
    );
    assert_eq!(
        artifacts.register("test:artifacts".parse().unwrap(), registration),
        Err(ProtocolRegistrationSetError::RetainedArtifactBytes {
            maximum: artifact_bytes - 1
        })
    );
    assert_eq!(artifacts.reference_count(), 0);
    assert_eq!(artifacts.registration_count(), 0);
    assert_eq!(artifacts.retained_artifact_bytes(), 0);
}

#[test]
fn execution_handles_are_context_local_root_scoped_and_generation_checked() {
    let fixture = Fixture::new();
    let protocol_ref: ProtocolRef = "test:lifecycle".parse().unwrap();
    let mut registrations = ProtocolRegistrationSet::default();
    registrations
        .register(protocol_ref.clone(), fixture.registration(11))
        .unwrap();

    let first = QueryAnalysisContext::new(
        &fixture.analyzer,
        11,
        &registrations,
        std::slice::from_ref(&protocol_ref),
    )
    .unwrap();
    let first_handle = first.handle(&protocol_ref).unwrap();
    assert!(
        first
            .resolve(&fixture.analyzer, 11, &fixture.root, first_handle)
            .is_ok()
    );

    let second = QueryAnalysisContext::new(
        &fixture.analyzer,
        11,
        &registrations,
        std::slice::from_ref(&protocol_ref),
    )
    .unwrap();
    let second_handle = second.handle(&protocol_ref).unwrap();
    assert_eq!(
        first
            .resolve(&fixture.analyzer, 11, &fixture.root, second_handle)
            .unwrap_err(),
        QueryAnalysisContextError::StaleHandle
    );
    assert_eq!(
        first
            .resolve(&fixture.analyzer, 12, &fixture.root, first_handle)
            .unwrap_err(),
        QueryAnalysisContextError::WorkspaceGenerationMismatch {
            registered: 11,
            current: 12
        }
    );

    let other_project = InlineTestProject::with_language(Language::TypeScript)
        .file("src/other.ts", "export function other() { return 2; }\n")
        .build();
    let other_analyzer = other_project.workspace_analyzer(AnalyzerConfig::default());
    let other_root = resolve_procedure_handle(
        &other_project,
        &other_analyzer,
        "src/other.ts",
        PointSelector::new("function other")
            .procedure("other")
            .effect("entry"),
    );
    assert_eq!(
        first
            .resolve(&fixture.analyzer, 11, &other_root, first_handle)
            .unwrap_err(),
        QueryAnalysisContextError::AnalysisRootMismatch
    );

    let rematerialized_analyzer = fixture
        .project
        .workspace_analyzer(AnalyzerConfig::default());
    let rematerialized_root = resolve_procedure_handle(
        &fixture.project,
        &rematerialized_analyzer,
        "src/main.ts",
        PointSelector::new("function lifecycle")
            .procedure("lifecycle")
            .effect("entry"),
    );
    assert!(!Arc::ptr_eq(
        fixture.root.artifact(),
        rematerialized_root.artifact()
    ));
    assert!(
        first
            .resolve(
                &rematerialized_analyzer,
                11,
                &rematerialized_root,
                first_handle,
            )
            .is_ok(),
        "durably identical rematerialized roots must survive cache eviction"
    );
}

#[test]
fn context_validation_is_bounded_cancellable_and_deduplicates_aliases() {
    let fixture = Fixture::new();
    let primary: ProtocolRef = "test:primary".parse().unwrap();
    let alias: ProtocolRef = "test:alias".parse().unwrap();
    let mut registrations = ProtocolRegistrationSet::default();
    registrations
        .register(primary.clone(), fixture.registration(5))
        .unwrap();
    registrations
        .register(alias.clone(), fixture.registration(5))
        .unwrap();

    QueryAnalysisContext::new_with_validation(
        &fixture.analyzer,
        5,
        &registrations,
        &[primary.clone(), alias.clone()],
        QueryAnalysisValidationLimits::new(1, SOURCE.len()),
        None,
    )
    .expect("aliases of one registration validate its artifact once");

    assert!(matches!(
        QueryAnalysisContext::new_with_validation(
            &fixture.analyzer,
            5,
            &registrations,
            std::slice::from_ref(&primary),
            QueryAnalysisValidationLimits::new(1, SOURCE.len() - 1),
            None,
        ),
        Err(QueryAnalysisContextError::ValidationBudgetExceeded {
            resource: "semantic artifact source bytes",
            maximum
        }) if maximum == SOURCE.len() - 1
    ));

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        QueryAnalysisContext::new_with_validation(
            &fixture.analyzer,
            5,
            &registrations,
            &[primary, alias],
            QueryAnalysisValidationLimits::default(),
            Some(&cancellation),
        )
        .unwrap_err(),
        QueryAnalysisContextError::Cancelled
    );
}

#[test]
fn context_rejects_unresolved_and_stale_semantic_artifacts() {
    let fixture = Fixture::new();
    let protocol_ref: ProtocolRef = "test:lifecycle".parse().unwrap();
    let registrations = ProtocolRegistrationSet::default();
    assert_eq!(
        QueryAnalysisContext::new(
            &fixture.analyzer,
            3,
            &registrations,
            std::slice::from_ref(&protocol_ref),
        )
        .unwrap_err(),
        QueryAnalysisContextError::UnresolvedReference {
            protocol_ref: protocol_ref.clone()
        }
    );

    let mut registrations = ProtocolRegistrationSet::default();
    registrations
        .register(protocol_ref.clone(), fixture.registration(3))
        .unwrap();
    fixture
        .project
        .file("src/main.ts")
        .write("export function lifecycle() { return 2; }\n")
        .unwrap();
    assert!(matches!(
        QueryAnalysisContext::new(
            &fixture.analyzer,
            3,
            &registrations,
            std::slice::from_ref(&protocol_ref),
        ),
        Err(QueryAnalysisContextError::StaleArtifact { ref path }) if path.as_ref() == "src/main.ts"
    ));
}
