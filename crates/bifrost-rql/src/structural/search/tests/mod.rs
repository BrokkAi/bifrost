use super::results::CodeQueryRowScalarRef;
use super::*;
use crate::analyzer::AnalyzerConfig;
use crate::analyzer::AnalyzerDelegate;
use crate::analyzer::CodeUnitType;
use crate::analyzer::JavaAnalyzer;
use crate::analyzer::JavascriptAnalyzer;
use crate::analyzer::MultiAnalyzer;
use crate::analyzer::OverlayProject;
use crate::analyzer::RustAnalyzer;
use crate::analyzer::ScalaAnalyzer;
use crate::analyzer::TestProject;
use crate::analyzer::TypescriptAnalyzer;
use crate::analyzer::WorkspaceAnalyzer;
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use brokk_bifrost_go_analysis::analyzer::GoAnalyzer;

use crate::structural::CodeQuery;
use brokk_bifrost_csharp_analysis::CSharpAnalyzer;
use brokk_bifrost_php_analysis::PhpAnalyzer;
use serde_json::json;
use std::cell::Cell;
use std::path::PathBuf;

#[path = "../../../../../../test-support/inline_project.rs"]
pub(super) mod inline_project;
use inline_project::InlineTestProject;

fn language_analyzer(language: Language, project: TestProject) -> Box<dyn IAnalyzer> {
    match language {
        Language::Cpp => Box::new(CppAnalyzer::from_project(project)),
        Language::CSharp => Box::new(CSharpAnalyzer::from_project(project)),
        Language::Go => Box::new(GoAnalyzer::from_project(project)),
        Language::Java => Box::new(JavaAnalyzer::from_project(project)),
        Language::JavaScript => Box::new(JavascriptAnalyzer::from_project(project)),
        Language::Php => Box::new(PhpAnalyzer::from_project(project)),
        Language::Python => Box::new(PythonAnalyzer::from_project(project)),
        Language::Ruby => Box::new(RubyAnalyzer::from_project(project)),
        Language::Rust => Box::new(RustAnalyzer::from_project(project)),
        Language::Scala => Box::new(ScalaAnalyzer::from_project(project)),
        Language::TypeScript => Box::new(TypescriptAnalyzer::from_project(project)),
        other => panic!("no structural differential fixture for {other:?}"),
    }
}

mod assignment_evidence;
mod branch_evidence;
mod call_site_correlations;
mod comments;
mod configuration;
mod contracts;
mod decorated_unit_provenance;
mod details;
mod environment_sessions;
mod execution;
mod execution_boundaries;
mod execution_contracts;
mod index_access;
mod js_rule_coverage;
mod materialization_coordinates;
mod provenance_identity;
mod public_response;
mod python_call_callee;
mod python_comment_blocks;
mod python_comparison;
mod python_imports;
mod python_iterator_properties;
mod python_method_receiver;
mod python_pythagorean;
mod python_raises;
mod python_scope_coverage;
mod python_workspace_authorities;
mod recovered_syntax;
mod relation_coverage;
mod row_identities;
mod rust_imports;
mod rust_task_and_callback;
mod seed_coverage;
mod selected_edges;
mod semantic_exhausted_roots;
mod semantic_inventory_limits;
mod session_and_trace_identities;
mod set_explanation;
mod structural_identity_filters;
mod unit_output_bounds;
mod unit_partition_properties;
mod unit_union_bounds;
mod units;

use brokk_bifrost_ruby_analysis::RubyAnalyzer;

use brokk_bifrost_cpp_analysis::analyzer::CppAnalyzer;

use brokk_bifrost_python_analysis::PythonAnalyzer;

mod callable_overload_facts;

mod python_definition_flags;
mod python_receiver_evaluation;
mod rune_rendering;
mod semantic_policy_contracts;
