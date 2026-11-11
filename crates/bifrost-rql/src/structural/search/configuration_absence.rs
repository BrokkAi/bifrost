//! Scoped configuration anti-joins.
//!
//! A negative configuration claim is only emitted for a complete document
//! arena. Routes in the filter remain absolute from the document root.

use super::configuration::fact_matches_filter;
use super::*;
use crate::query::ConfigurationAbsenceScope;
use crate::query::ConfigurationFactsFilter;

/// Shared by the rows of one pipeline step, then dropped with that step.
#[derive(Default)]
pub(super) struct AbsenceStepMemo {
    documents: HashMap<(ProjectFile, usize), AbsenceDocumentMemo>,
    /// Files whose incomplete answer this step has reported, so every row of
    /// one document does not repeat the same diagnostic.
    reported_partial_documents: HashSet<ProjectFile>,
    reported_undecodable_documents: HashSet<ProjectFile>,
}

struct AbsenceDocumentMemo {
    // Keep the arena alive so its address remains a valid memo key until this step ends.
    document: Arc<brokk_bifrost_core::analyzer::configuration::ConfigurationDocumentFacts>,
    document_matches: Option<Option<bool>>,
    children: Option<Vec<Vec<usize>>>,
}

pub(super) fn expansions(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
    memo: &mut AbsenceStepMemo,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    if !value.document.completeness().is_complete() {
        if !memo.reported_partial_documents.insert(value.file.clone()) {
            return Vec::new();
        }
        diagnostics.push(incomplete_diagnostic(
            CodeQueryDiagnosticCode::SemanticAnalysisPartial,
            brokk_bifrost_rql::Incompleteness::Content,
            "workspace",
            format!(
                "configuration_absence cannot prove absence in partly recovered document {}",
                rel_path_string(value.file())
            ),
            Vec::new(),
        ));
        return Vec::new();
    }

    let identity = (value.file.clone(), Arc::as_ptr(&value.document) as usize);
    let document = memo
        .documents
        .entry(identity)
        .or_insert_with(|| AbsenceDocumentMemo {
            document: Arc::clone(&value.document),
            document_matches: None,
            children: None,
        });
    debug_assert!(Arc::ptr_eq(&document.document, &value.document));
    let matches = match filter.absence_scope {
        ConfigurationAbsenceScope::Document => {
            *document.document_matches.get_or_insert_with(|| {
                let region = (0..value.document.facts().len()).collect::<Vec<_>>();
                matches_in_region(value, filter, &region)
            })
        }
        ConfigurationAbsenceScope::Subtree => {
            let children = document.children.get_or_insert_with(|| {
                let mut children = vec![Vec::new(); value.document.facts().len()];
                for (index, fact) in value.document.facts().iter().enumerate() {
                    if let Some(parent) = fact.parent() {
                        children[parent.index()].push(index);
                    }
                }
                children
            });
            let region = subtree_indices(value.index, children);
            matches_in_region(value, filter, &region)
        }
    };
    match matches {
        Some(true) => Vec::new(),
        Some(false) => vec![pipeline_expansion(PipelineValue::ConfigurationFact(
            value.clone(),
        ))],
        None => {
            if !memo
                .reported_undecodable_documents
                .insert(value.file.clone())
            {
                return Vec::new();
            }
            diagnostics.push(incomplete_diagnostic(
                CodeQueryDiagnosticCode::SemanticAnalysisPartial,
                brokk_bifrost_rql::Incompleteness::Content,
                "workspace",
                format!(
                    "configuration_absence cannot decode a scalar in {}",
                    rel_path_string(value.file())
                ),
                Vec::new(),
            ));
            Vec::new()
        }
    }
}

fn subtree_indices(base: usize, children: &[Vec<usize>]) -> Vec<usize> {
    let mut stack = vec![base];
    let mut region = Vec::new();
    while let Some(index) = stack.pop() {
        region.push(index);
        stack.extend(children[index].iter().copied());
    }
    region
}

fn matches_in_region(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
    region: &[usize],
) -> Option<bool> {
    let mut undecodable = false;
    for &index in region {
        let candidate = ConfigurationFactValue {
            file: value.file.clone(),
            document: Arc::clone(&value.document),
            source: Arc::clone(&value.source),
            index,
        };
        match fact_matches_filter(&candidate, filter) {
            Ok(true) => return Some(true),
            Ok(false) => {}
            Err(()) => undecodable = true,
        }
    }
    (!undecodable).then_some(false)
}
