//! Report-only interpretation of selected-environment absence. Ordinary usage
//! queries keep their query obligations. All inventories here die with the report.
use super::{
    PythonAnalyzer,
    native_request::{PythonNativeOpen, open_python_native_request},
};
use brokk_bifrost_analysis::analyzer::languages::DeadCodeCoverage;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::{Result, StoreError};
use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;
use brokk_bifrost_analysis::analyzer::usages::get_type::{
    TypeLookupRequest, TypeLookupStatus, resolve_type_batch,
};
use brokk_bifrost_analysis::analyzer::{CodeUnit, IAnalyzer, ProjectFile};
use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
use brokk_bifrost_core::analyzer::usages::model::FuzzyResult;
use brokk_bifrost_core::cancellation::CancellationToken;

pub(super) fn reason_is_scope(reason: &EdgeIncompleteReason) -> bool {
    matches!(reason, EdgeIncompleteReason::UsageAnalysisFailed { reason_kind, .. }
        if matches!(reason_kind.as_str(), "python_environment_open" | "python_unknown_placement" | "python_dynamic_receiver_mutation_open"))
}

pub(super) fn usage_result(result: FuzzyResult) -> FuzzyResult {
    let FuzzyResult::Incomplete {
        hits_by_overload,
        unproven_by_overload,
        unproven_total_by_overload,
        mut diagnostics,
    } = result
    else {
        return result;
    };
    // Writes do not constitute reads. Scope obligations remain stated once in
    // the report. All reference-attributable losses and limits stay untouched.
    diagnostics.retain(|diagnostic| {
        !matches!(
            diagnostic.reason_kind.as_str(),
            "python_environment_open"
                | "python_unknown_placement"
                | "python_dynamic_receiver_mutation_open"
        )
    });
    if diagnostics.is_empty() {
        FuzzyResult::Success {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
        }
    } else {
        FuzzyResult::Incomplete {
            hits_by_overload,
            unproven_by_overload,
            unproven_total_by_overload,
            diagnostics,
        }
    }
}

pub(super) fn coverage(
    analyzer: &dyn IAnalyzer,
    candidates: &[CodeUnit],
) -> Result<DeadCodeCoverage> {
    let python = resolve_analyzer::<PythonAnalyzer>(analyzer)
        .ok_or_else(|| StoreError::new("selected Python analyzer unavailable"))?;
    let cancellation = CancellationToken::default();
    let request = match open_python_native_request(python, &cancellation)? {
        PythonNativeOpen::Ready(request) => request,
        PythonNativeOpen::Unavailable { kind, message } => {
            return Err(StoreError::new(format!("{kind}: {message}")));
        }
        PythonNativeOpen::Cancelled => {
            return Err(StoreError::new("selected Python coverage cancelled"));
        }
    };
    let (obligations, _) = request
        .operation
        .python_graph_input_evidence(&request.environment, &cancellation)?;
    let components = obligations
        .iter()
        .filter(|label| {
            label.starts_with("python_environment_open:")
                || label.starts_with("python_unknown_placement:")
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut coverage = DeadCodeCoverage {
        note: Some(format!(
            "Python absence and usage counts are relative to the selected environment; open components: {components:?}. Dynamic receiver mutation alone does not constitute a usage."
        )),
        ..Default::default()
    };
    // Unknown names nominate no reverse targets. Ask the retained source
    // inventory directly, including for fields handled by precise reverse.
    // effect=0 is a read; writes/deletes are deliberately not included.
    let reads = request.operation.ready().inventory.connection().prepare_cached(
        "SELECT mounts.persisted_relative_path,site.start_byte,site.end_byte,op.name_kind,
                (SELECT json_group_array(spelling) FROM python_member_operation_names names WHERE names.operation=op.id)
         FROM temp.selected_resolution_mounts mounts
         JOIN resolution_unit_summary_members member ON member.summary_id=?1
          AND member.blob_id=mounts.blob_id AND member.rel_path=mounts.persisted_relative_path
         JOIN python_member_operations op ON op.blob_id=mounts.blob_id AND op.effect=0 AND op.name_kind<>0
         JOIN python_member_sites site ON site.blob_id=op.blob_id AND site.site=op.site
         WHERE mounts.storage_language='python'
         ORDER BY mounts.persisted_relative_path,op.site")?
        .query_map([request.environment.summary], |row| Ok((row.get::<_,String>(0)?, row.get::<_,usize>(1)?,row.get::<_,usize>(2)?,row.get::<_,u8>(3)?,row.get::<_,String>(4)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (path, start, end, name_kind, names) in reads {
        let prefixes: Vec<String> = serde_json::from_str(&names).map_err(|error| {
            StoreError::corrupt(format!("invalid dynamic member names: {error}"))
        })?;
        let file = ProjectFile::new(analyzer.project().root(), &path);
        let source = python.indexed_source(&file).ok_or_else(|| {
            StoreError::new(format!("unknown-name read source unavailable: {file}"))
        })?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        let tree = parser.parse(source.as_str(), None).ok_or_else(|| {
            StoreError::new(format!("unknown-name read parse unavailable: {file}"))
        })?;
        let call = tree.root_node().descendant_for_byte_range(start, end);
        let receiver = call
            .filter(|node| node.kind() == "call")
            .and_then(|call| call.child_by_field_name("arguments"))
            .and_then(|arguments| arguments.named_child(0));
        let types = receiver.map(|receiver| {
            resolve_type_batch(
                analyzer,
                vec![TypeLookupRequest {
                    file: file.clone(),
                    source: Some(std::sync::Arc::new(source.clone())),
                    line: None,
                    column: None,
                    start_byte: Some(receiver.start_byte()),
                    end_byte: Some(receiver.end_byte()),
                }],
            )
            .pop()
            .expect("one receiver lookup")
        });
        // A closed class type excludes module objects in this selected type
        // interpretation. Keep every class member possible: a nominal receiver
        // may have a subtype combining otherwise unrelated owners by multiple
        // inheritance. Unknown receivers exclude neither classes nor modules.
        let owners = types
            .filter(|answer| answer.status == TypeLookupStatus::Resolved && answer.types.len() == 1)
            .and_then(|answer| {
                let definitions = &answer.types[0].definitions;
                (definitions.len() == 1
                    && definitions[0].is_class()
                    && !definitions[0].is_synthetic())
                .then(|| definitions[0].clone())
            });
        for candidate in candidates {
            if name_kind == 1
                && !prefixes
                    .iter()
                    .any(|prefix| candidate.terminal_name().starts_with(prefix))
            {
                continue;
            }
            let could_reach = owners.as_ref().is_none_or(|_| {
                analyzer
                    .parent_of(candidate)
                    .is_some_and(|owner| owner.is_class())
            });
            if could_reach {
                coverage.vetoes.entry(candidate.declaration_id()).or_insert_with(|| format!(
                    "python_unknown_member_name read at {path}:{start}..{end} can reach this declaration's owner"));
            }
        }
        if coverage.vetoes.len() == candidates.len() {
            break;
        }
    }
    Ok(coverage)
}
