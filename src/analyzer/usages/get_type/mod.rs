use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{RustTypeLookupCache, parse_tree_for_language};
use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, SourceLocationRequest, resolve_reference_site,
};
use crate::analyzer::usages::scala_graph::ScalaProjectTypes;
use crate::analyzer::{CodeUnit, DefinitionLookupIndex, IAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use std::sync::Arc;
use tree_sitter::Tree;

mod csharp;
mod go;
mod java;
mod js_ts;
mod rust;
mod scala;

#[derive(Debug, Clone)]
pub(crate) struct TypeLookupRequest {
    pub(crate) file: ProjectFile,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) start_byte: Option<usize>,
    pub(crate) end_byte: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct TypeLookupOutcome {
    pub(crate) status: TypeLookupStatus,
    pub(crate) reference: Option<ResolvedReferenceSite>,
    pub(crate) types: Vec<TypeLookupType>,
    pub(crate) diagnostics: Vec<TypeLookupDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeLookupStatus {
    Resolved,
    NoType,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
}

impl TypeLookupStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NoType => "no_type",
            Self::Ambiguous => "ambiguous",
            Self::UnsupportedLanguage => "unsupported_language",
            Self::InvalidLocation => "invalid_location",
            Self::NotFound => "not_found",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TypeLookupDiagnostic {
    pub(crate) kind: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TypeLookupType {
    pub(crate) fqn: String,
    pub(crate) definitions: Vec<CodeUnit>,
}

pub(crate) fn resolve_type_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<TypeLookupRequest>,
) -> Vec<TypeLookupOutcome> {
    let mut context = TypeBatchContext::new(analyzer);
    requests
        .into_iter()
        .map(|request| resolve_one(analyzer, &mut context, request))
        .collect()
}

struct TypeBatchContext<'a> {
    support: &'a DefinitionLookupIndex,
    sources: HashMap<ProjectFile, Result<Arc<String>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    rust_cache: RustTypeLookupCache,
    scala_project_types: Option<Arc<ScalaProjectTypes>>,
}

impl<'a> TypeBatchContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            support: analyzer.definition_lookup_index(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            rust_cache: RustTypeLookupCache::default(),
            scala_project_types: None,
        }
    }

    fn source(&mut self, file: &ProjectFile) -> Result<Arc<String>, String> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                file.read_to_string()
                    .map(Arc::new)
                    .map_err(|err| format!("failed to read `{}`: {err}", rel_path_string(file)))
            })
            .clone()
    }

    fn tree(&mut self, file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
        self.trees
            .entry((file.clone(), language))
            .or_insert_with(|| parse_tree_for_type_lookup(file, language, source))
            .clone()
    }

    fn scala_project_types(
        &mut self,
        scala: &crate::analyzer::ScalaAnalyzer,
    ) -> Arc<ScalaProjectTypes> {
        self.scala_project_types
            .get_or_insert_with(|| Arc::new(ScalaProjectTypes::build(scala)))
            .clone()
    }
}

fn resolve_one(
    analyzer: &dyn IAnalyzer,
    context: &mut TypeBatchContext<'_>,
    request: TypeLookupRequest,
) -> TypeLookupOutcome {
    let file = request.file.clone();
    let language = language_for_file(&file);
    let source = match context.source(&file) {
        Ok(source) => source,
        Err(message) => {
            return diagnostic_outcome(TypeLookupStatus::NotFound, "file_read_failed", message);
        }
    };
    let site = match resolve_reference_site(&request.as_source_location(), &source) {
        Ok(site) => site,
        Err(message) => {
            return diagnostic_outcome(
                TypeLookupStatus::InvalidLocation,
                "invalid_location",
                message,
            );
        }
    };

    if !matches!(
        language,
        Language::CSharp
            | Language::Go
            | Language::Java
            | Language::JavaScript
            | Language::Rust
            | Language::Scala
            | Language::TypeScript
    ) {
        return finish_lookup_outcome(
            diagnostic_outcome(
                TypeLookupStatus::UnsupportedLanguage,
                "unsupported_language",
                format!("{language:?} type lookup is not implemented yet"),
            ),
            site,
        );
    }

    let tree = context.tree(&file, language, &source);
    let resolved = match language {
        Language::CSharp => {
            csharp::resolve_csharp_type(analyzer, &file, &source, tree.as_ref(), &site)
        }
        Language::Go => go::resolve_go_type(analyzer, &file, &source, tree.as_ref(), &site),
        Language::Java => java::resolve_java_type(analyzer, &file, &source, tree.as_ref(), &site),
        Language::JavaScript | Language::TypeScript => js_ts::resolve_js_ts_type(
            analyzer,
            context.support,
            &file,
            language,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Rust => rust::resolve_rust_type(
            analyzer,
            &file,
            &source,
            tree.as_ref(),
            &site,
            &mut context.rust_cache,
        ),
        Language::Scala => {
            scala::resolve_scala_type(analyzer, context, &file, &source, tree.as_ref(), &site)
        }
        _ => unreachable!("unsupported language handled above"),
    };
    finish_lookup_outcome(resolved, site)
}

fn finish_lookup_outcome(
    mut outcome: TypeLookupOutcome,
    site: ResolvedReferenceSite,
) -> TypeLookupOutcome {
    outcome.reference = Some(site);
    outcome
}

impl TypeLookupRequest {
    fn as_source_location(&self) -> SourceLocationRequest {
        SourceLocationRequest {
            file: self.file.clone(),
            line: self.line,
            column: self.column,
            start_byte: self.start_byte,
            end_byte: self.end_byte,
        }
    }
}

fn parse_tree_for_type_lookup(
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    match language {
        Language::Go => {
            let mut parser = tree_sitter::Parser::new();
            parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
            parser.parse(source, None)
        }
        _ => parse_tree_for_language(file, language, source),
    }
}

pub(super) fn candidates_outcome(
    fqn: impl Into<String>,
    mut candidates: Vec<CodeUnit>,
) -> TypeLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    let mut semantic_keys = HashSet::default();
    for candidate in &candidates {
        semantic_keys.insert((candidate.fq_name(), candidate.source().clone()));
    }
    let status = if semantic_keys.len() <= 1 {
        TypeLookupStatus::Resolved
    } else {
        TypeLookupStatus::Ambiguous
    };
    TypeLookupOutcome {
        status,
        reference: None,
        types: vec![TypeLookupType {
            fqn: fqn.into(),
            definitions: candidates,
        }],
        diagnostics: if status == TypeLookupStatus::Ambiguous {
            vec![TypeLookupDiagnostic {
                kind: "ambiguous_type".to_string(),
                message: "reference resolved to multiple possible types".to_string(),
            }]
        } else {
            Vec::new()
        },
    }
}

pub(super) fn no_type(kind: impl Into<String>, message: impl Into<String>) -> TypeLookupOutcome {
    diagnostic_outcome(TypeLookupStatus::NoType, kind, message)
}

fn diagnostic_outcome(
    status: TypeLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> TypeLookupOutcome {
    TypeLookupOutcome {
        status,
        reference: None,
        types: Vec::new(),
        diagnostics: vec![TypeLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
    }
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        left.fq_name()
            .cmp(&right.fq_name())
            .then_with(|| left.source().cmp(right.source()))
    });
}
