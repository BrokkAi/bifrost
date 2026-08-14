use super::results::{ALL_DETAILED_CODE_QUERY_DOMAINS, CodeQueryRowScalarRef};
use super::*;
use crate::analyzer::structural::CodeQuery;
use crate::analyzer::usages::get_definition::ResolvedReferenceSite;
use crate::analyzer::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CodeUnitType, CppAnalyzer, GoAnalyzer,
    JavaAnalyzer, JavascriptAnalyzer, MultiAnalyzer, OverlayProject, PhpAnalyzer, PythonAnalyzer,
    RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, TestProject, TypescriptAnalyzer, WorkspaceAnalyzer,
};
use serde_json::json;
use std::cell::Cell;
use std::path::PathBuf;

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

mod contracts;
mod details;
mod execution;
mod index_access;
