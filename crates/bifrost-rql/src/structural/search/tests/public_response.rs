use super::*;

#[test]
fn exhausted_root_prose_preserves_complete_structured_attribution() {
    let roots: Vec<_> = (0..100)
        .map(|index| CodeQueryExhaustedRoot {
            path: format!("src/{index}/{}.py", "long_directory/".repeat(12)),
            procedure: Some("process".into()),
            lane: "solver/reached_states".into(),
            stage: Some("value_flow_solve".into()),
            charge: None,
            feedback_iteration: None,
        })
        .collect();
    let message = results::render_exhausted_roots(
        "work exhausted",
        &roots,
        results::MAX_DIAGNOSTIC_LIST_MESSAGE_BYTES,
    );
    assert!(message.len() <= 3_584, "{message}");
    let shown = message
        .lines()
        .filter(|line| line.starts_with("- src/"))
        .count();
    assert!(shown > 0 && shown < 100);
    assert!(message.ends_with(&format!("\n- [{} more in exhausted_roots]", 100 - shown)));
}

#[test]
fn invalid_typed_pipeline_returns_workspace_invalid_diagnostic() {
    let project = InlineTestProject::with_language(Language::Python)
        .file("main.py", "def target():\n    pass\n")
        .build();
    let analyzer = PythonAnalyzer::from_project(crate::analyzer::FileSetProject::new(
        project.root(),
        [PathBuf::from("main.py")],
    ));
    let mut query = CodeQuery::from_json(&json!({"match": {"kind": "function"}})).unwrap();
    // Import traversal consumes files, while this seed supplies syntax rows.
    query.plan.steps.push(QueryStep::ImportsOf);
    let response = execute_request(&analyzer, &query);
    let result = response.result().expect("result response");
    assert!(result.results.is_empty(), "{result:?}");
    assert!(!result.truncated);
    assert_eq!(
        serde_json::to_value(result.session_subset).unwrap(),
        json!({"files": 1})
    );
    assert_eq!(result.diagnostics.len(), 1, "{result:?}");
    let diagnostic = &result.diagnostics[0];
    assert_eq!(diagnostic.code, CodeQueryDiagnosticCode::InvalidPlan);
    assert_eq!(diagnostic.impact, CodeQueryDiagnosticImpact::Invalid);
    assert_eq!(diagnostic.language, "workspace");
}

#[test]
fn callable_signature_text_states_required_and_defaulted_arity() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            "def required(a, b):\n    pass\ndef defaulted(a, b=1):\n    pass\n",
        )
        .build();
    let analyzer = PythonAnalyzer::from_project(project.project().clone());
    let query = CodeQuery::from_json(&json!({
        "match": {"kind": "function"}, "steps": [{"op": "enclosing_decl"}, {"op": "callable_signature"}]
    }))
    .unwrap();
    let result = execute(&analyzer, &query);
    assert_eq!(result.results.len(), 2, "{result:?}");
    let text = result.render_text();
    assert!(
        text.lines().any(|line| line.contains("required arity=2 ")),
        "{text}"
    );
    assert!(
        text.lines()
            .any(|line| line.contains("defaulted arity=1..2 ")),
        "{text}"
    );
}

use crate::analyzer::CodeUnitIndex;
#[derive(Clone)]
struct MissingFactsAnalyzer {
    inner: PhpAnalyzer,
    outcome: crate::analyzer::structural::provider::StructuralFactsCacheOutcome,
}

impl CodeUnitIndex for MissingFactsAnalyzer {
    fn project(&self) -> &dyn crate::analyzer::Project {
        CodeUnitIndex::project(&self.inner)
    }

    fn languages(&self) -> BTreeSet<Language> {
        CodeUnitIndex::languages(&self.inner)
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        CodeUnitIndex::all_declarations(&self.inner)
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        CodeUnitIndex::search_definitions(&self.inner, pattern, auto_quote)
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit(&self.inner, file, range)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        CodeUnitIndex::enclosing_code_unit_for_lines(&self.inner, file, start_line, end_line)
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton(&self.inner, code_unit)
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        CodeUnitIndex::get_skeleton_header(&self.inner, code_unit)
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        CodeUnitIndex::get_source(&self.inner, code_unit, include_comments)
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        CodeUnitIndex::get_sources(&self.inner, code_unit, include_comments)
    }
}

impl IAnalyzer for MissingFactsAnalyzer {
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        Self {
            inner: IAnalyzer::update(&self.inner, changed_files),
            outcome: self.outcome,
        }
    }

    fn update_all(&self) -> Self {
        Self {
            inner: IAnalyzer::update_all(&self.inner),
            outcome: self.outcome,
        }
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        IAnalyzer::extract_call_receiver(&self.inner, reference)
    }

    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool {
        IAnalyzer::is_access_expression(&self.inner, file, start_byte, end_byte)
    }

    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<crate::analyzer::DeclarationInfo> {
        IAnalyzer::find_nearest_declaration(&self.inner, file, start_byte, end_byte, ident)
    }

    fn structural_fact_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralFactProvider> {
        vec![self]
    }
}

use crate::analyzer::structural::resolution::*;
use crate::analyzer::structural::*;

impl crate::analyzer::structural::StructuralFactProvider for MissingFactsAnalyzer {
    fn structural_extraction_count(&self) -> u64 {
        self.inner.structural_fact_providers()[0].structural_extraction_count()
    }
    fn structural_hydration_count(&self) -> u64 {
        self.inner.structural_fact_providers()[0].structural_hydration_count()
    }
    fn structural_supports_kind(&self, value: NormalizedKind) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_kind(value)
    }
    fn structural_supports_role(&self, value: Role) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_role(value)
    }
    fn structural_supports_occurrence_role(&self, value: OccurrenceRole) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_occurrence_role(value)
    }
    fn structural_supports_environment_axis(&self, value: EnvironmentAxis) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_environment_axis(value)
    }
    fn structural_supports_materialization_axis(&self, value: MaterializationAxis) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_materialization_axis(value)
    }
    fn structural_supports_edge_axis(&self, value: EdgeAxis) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_edge_axis(value)
    }
    fn structural_supports_identity_axis(&self, value: IdentityAxis) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_identity_axis(value)
    }
    fn structural_supports_route_relation(&self, value: RouteHopKind) -> bool {
        self.inner.structural_fact_providers()[0].structural_supports_route_relation(value)
    }

    fn structural_language(&self) -> Language {
        Language::Php
    }
    fn structural_files(&self) -> Vec<ProjectFile> {
        self.inner.structural_fact_providers()[0].structural_files()
    }
    fn structural_source(&self, file: &ProjectFile) -> Option<String> {
        self.inner.structural_fact_providers()[0].structural_source(file)
    }
    fn structural_facts(
        &self,
        _file: &ProjectFile,
    ) -> Option<Arc<crate::structural::facts::FileFacts>> {
        None
    }
    fn structural_facts_with_outcome(
        &self,
        _file: &ProjectFile,
    ) -> (
        Option<Arc<crate::structural::facts::FileFacts>>,
        crate::analyzer::structural::provider::StructuralFactsCacheOutcome,
    ) {
        (None, self.outcome)
    }
}

#[test]
fn profiled_missing_facts_distinguish_unavailable_from_unknown() {
    use crate::analyzer::structural::provider::StructuralFactsCacheOutcome;
    for outcome in [
        StructuralFactsCacheOutcome::Unavailable,
        StructuralFactsCacheOutcome::Unknown,
    ] {
        let project = InlineTestProject::with_language(Language::Php)
            .file("main.php", "<?php function target() {}\n")
            .build();
        let analyzer = MissingFactsAnalyzer {
            inner: PhpAnalyzer::from_project(project.project().clone()),
            outcome,
        };
        let query = CodeQuery::from_json(&json!({
            "match": {"kind": "function"}, "execution_mode": "profile"
        }))
        .unwrap();
        let CodeQueryResponse::Profile(profile) = execute_request(&analyzer, &query) else {
            panic!("expected profiled response");
        };
        assert!(profile.result.results.is_empty());
        let counters = profile
            .cache_layers
            .iter()
            .find_map(|layer| match layer {
                crate::structural::CodeQueryProfileCacheLayer::SeedStructuralFacts { metrics } => {
                    Some(metrics)
                }
                _ => None,
            })
            .expect("structural fact counters");
        assert_eq!(counters.lookups, 1);
        assert_eq!(
            counters.unavailable,
            u64::from(outcome == StructuralFactsCacheOutcome::Unavailable)
        );
        assert_eq!(
            counters.unknown_outcomes,
            u64::from(outcome == StructuralFactsCacheOutcome::Unknown)
        );
        assert_eq!(counters.memory_hits, 0);
        assert_eq!(counters.persisted_hydrations, 0);
        assert_eq!(counters.extractions, 0);
    }
}
