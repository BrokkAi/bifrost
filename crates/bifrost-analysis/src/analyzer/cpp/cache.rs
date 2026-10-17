use super::*;
use brokk_bifrost_cpp::declarations::CppRecoveredExportClassIndex;
use brokk_bifrost_cpp::graph::resolver::{
    CppClassDeclarationStrength, EffectiveUsingTarget, OrdinaryTypeImport,
    OrphanedNamespaceScopeIndex, PreprocessorGuard,
};
use std::mem::size_of;
use std::sync::Arc;

pub(super) fn weight_macro_composed_field_vec_by_file(
    _key: &ProjectFile,
    value: &Arc<Vec<super::MacroComposedField>>,
) -> u32 {
    let source_bytes = value.first().map_or(0, |first| {
        assert!(
            value
                .iter()
                .all(|field| Arc::ptr_eq(&first.source, &field.source)),
            "macro-composed fields must share one canonical source arena"
        );
        first.source.estimated_retained_bytes()
    });
    let size = value
        .iter()
        .fold(size_of::<Vec<super::MacroComposedField>>(), |acc, field| {
            acc.saturating_add(size_of::<super::MacroComposedField>())
                .saturating_add(weight_code_unit(&field.owner))
                .saturating_add(field.unit.fq_name().len())
                .saturating_add(field.unit.short_name().len())
                .saturating_add(field.unit.package_name().len())
                .saturating_add(field.unit.signature().map_or(0, str::len))
                .saturating_add(field.ranges.len().saturating_mul(size_of::<Range>()))
        })
        .saturating_add(source_bytes);
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_cpp_file_facts(
    _key: &ProjectFile,
    value: &Arc<super::semantic::CppFileFacts>,
) -> u32 {
    value.estimated_retained_bytes().clamp(1, u32::MAX as usize) as u32
}

pub(super) fn weight_statement_fact_rows(
    _key: &ProjectFile,
    value: &Arc<brokk_bifrost_core::analyzer::statement_facts::CppStatementFactRows>,
) -> u32 {
    value.estimated_retained_bytes().clamp(1, u32::MAX as usize) as u32
}

pub(super) fn weight_call_macro_hazards(
    _key: &ProjectFile,
    value: &Arc<HashMap<(usize, usize), bool>>,
) -> u32 {
    let size = size_of::<HashMap<(usize, usize), bool>>().saturating_add(
        value
            .len()
            .saturating_mul(size_of::<((usize, usize), bool)>()),
    );
    size.clamp(1, u32::MAX as usize) as u32
}

pub(super) fn weight_c_assignment_candidates(
    _key: &(
        crate::analyzer::semantic::SemanticArtifactMaterializationId,
        crate::analyzer::semantic::ProcedureId,
    ),
    value: &Arc<super::expression_branch_facts::CAssignmentCandidates>,
) -> u32 {
    let size = size_of::<super::expression_branch_facts::CAssignmentCandidates>().saturating_add(
        value.rows.capacity().saturating_mul(size_of::<
            super::expression_branch_facts::CAssignmentCandidate,
        >()),
    );
    size.clamp(1, u32::MAX as usize) as u32
}

pub(super) fn weight_cpp_overwritten_candidates(
    _key: &super::CAssignmentCandidateKey,
    value: &Arc<super::OverwrittenLocalCandidates>,
) -> u32 {
    let rows = value.rows.iter().fold(
        size_of::<super::OverwrittenLocalCandidates>(),
        |size, row| {
            size.saturating_add(size_of::<
                crate::analyzer::assignment_facts::OverwrittenLocalCandidate,
            >())
            .saturating_add(
                row.points
                    .capacity()
                    .saturating_mul(size_of::<crate::analyzer::semantic::ProgramPointId>()),
            )
        },
    );
    rows.saturating_add(value.rows.capacity().saturating_mul(size_of::<
        crate::analyzer::assignment_facts::OverwrittenLocalCandidate,
    >()))
    .clamp(1, u32::MAX as usize) as u32
}

pub(super) fn weight_code_unit_set_by_file(
    _key: &ProjectFile,
    value: &Arc<HashSet<CodeUnit>>,
) -> u32 {
    let size = value.iter().fold(0usize, |acc, item| {
        acc + size_of::<CodeUnit>()
            + item.fq_name().len()
            + item.short_name().len()
            + item.package_name().len()
            + item.signature().map_or(0, str::len)
    });
    size.saturating_add(size_of::<HashSet<CodeUnit>>())
        .min(u32::MAX as usize) as u32
}

pub(super) fn weight_code_unit_vec_by_file(_key: &ProjectFile, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value.iter().fold(size_of::<Vec<CodeUnit>>(), |acc, item| {
        let item_size = size_of::<CodeUnit>()
            .saturating_add(item.fq_name().len())
            .saturating_add(item.short_name().len())
            .saturating_add(item.package_name().len())
            .saturating_add(item.signature().map_or(0, str::len));
        acc.saturating_add(item_size)
    });
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_project_file_set(
    _key: &ProjectFile,
    value: &Arc<HashSet<ProjectFile>>,
) -> u32 {
    let size = value.iter().fold(0usize, |acc, item| {
        acc + size_of::<ProjectFile>()
            + item.root().as_os_str().len()
            + item.rel_path().as_os_str().len()
    });
    size.saturating_add(size_of::<HashSet<ProjectFile>>())
        .min(u32::MAX as usize) as u32
}

pub(super) fn weight_include_reachability(
    key: &(ProjectFile, ProjectFile, ProjectFile),
    _value: &bool,
) -> u32 {
    let (first, donor, reference) = key;
    let size = size_of::<(ProjectFile, ProjectFile, ProjectFile)>()
        .saturating_add(first.root().as_os_str().len())
        .saturating_add(first.rel_path().as_os_str().len())
        .saturating_add(donor.root().as_os_str().len())
        .saturating_add(donor.rel_path().as_os_str().len())
        .saturating_add(reference.root().as_os_str().len())
        .saturating_add(reference.rel_path().as_os_str().len());
    size.clamp(1, u32::MAX as usize) as u32
}

fn weight_code_unit(unit: &CodeUnit) -> usize {
    size_of::<CodeUnit>()
        .saturating_add(unit.fq_name().len())
        .saturating_add(unit.short_name().len())
        .saturating_add(unit.package_name().len())
        .saturating_add(unit.signature().map_or(0, str::len))
}

/// #1908: one entry is every callable declaration sharing a member identifier,
/// bucketed by owner terminal, so a hot identifier on a whale repo is thousands
/// of units. Weighed by content like its siblings rather than counted, so the
/// cell cannot hold an unbounded amount of the workspace.
// `&String`, not `&str`: moka's weigher is `Fn(&K, &V)` and the cell is keyed
// by `String`.
#[allow(clippy::ptr_arg)]
pub(super) fn weight_reconcile_candidates(
    key: &String,
    value: &Arc<CppReconcileCandidates>,
) -> u32 {
    // Bucketed units are clones of the same `CodeUnit`s, so charge each
    // candidate's content once and every bucket entry at the unit's own size.
    let size = value
        .iter()
        .fold(size_of::<CppReconcileCandidates>(), |acc, item| {
            acc.saturating_add(weight_code_unit(item))
        })
        .saturating_add(value.bucketed_len().saturating_mul(size_of::<CodeUnit>()))
        .saturating_add(key.len());
    size.clamp(1, u32::MAX as usize) as u32
}

fn weight_string_components(components: &[String]) -> usize {
    components
        .iter()
        .fold(size_of::<Vec<String>>(), |acc, component| {
            acc.saturating_add(size_of::<String>())
                .saturating_add(component.len())
        })
}

fn weight_ordinary_type_import(binding: &OrdinaryTypeImport) -> usize {
    let target = match &binding.target {
        EffectiveUsingTarget::Ordinary {
            name,
            target_components,
            ..
        } => name
            .len()
            .saturating_add(weight_string_components(target_components)),
        EffectiveUsingTarget::Namespace {
            namespace_components,
            ..
        } => weight_string_components(namespace_components),
    };
    let guards = binding.required_guards.iter().fold(
        size_of::<HashSet<PreprocessorGuard>>(),
        |acc, guard| {
            let text = match guard {
                PreprocessorGuard::Defined(name) | PreprocessorGuard::Undefined(name) => name.len(),
                PreprocessorGuard::Boolean(expression) => expression.heap_size(),
                PreprocessorGuard::Expression(expression)
                | PreprocessorGuard::NegatedExpression(expression) => expression.len(),
                PreprocessorGuard::Constant(_) => 0,
            };
            acc.saturating_add(size_of::<PreprocessorGuard>())
                .saturating_add(text)
        },
    );
    size_of::<OrdinaryTypeImport>()
        .saturating_add(target)
        .saturating_add(binding.source.root().as_os_str().len())
        .saturating_add(binding.source.rel_path().as_os_str().len())
        .saturating_add(weight_string_components(&binding.declaration_namespace))
        .saturating_add(
            binding
                .namespace_scope
                .as_deref()
                .map_or(0, weight_string_components),
        )
        .saturating_add(
            binding
                .resolved_target_components
                .as_deref()
                .map_or(0, weight_string_components),
        )
        .saturating_add(guards)
}

/// #1927: one entry is every structured using declaration one file carries,
/// keyed by imported name plus the file's using-directives.
pub(super) fn weight_source_using_index(_key: &ProjectFile, value: &Arc<SourceUsingIndex>) -> u32 {
    let size = value
        .ordinary_by_name
        .iter()
        .fold(size_of::<SourceUsingIndex>(), |acc, (name, bindings)| {
            bindings
                .iter()
                .fold(acc.saturating_add(name.len()), |acc, binding| {
                    acc.saturating_add(weight_ordinary_type_import(binding))
                })
        })
        .saturating_add(value.directives.iter().fold(0usize, |acc, binding| {
            acc.saturating_add(weight_ordinary_type_import(binding))
        }));
    size.clamp(1, u32::MAX as usize) as u32
}

/// #1908: one entry is every re-keyed definition one (identifier, owner
/// terminal) group produces, grouped under its canonical fq name.
pub(super) fn weight_reconciled_groups(
    key: &CppReconcileGroupKey,
    value: &Arc<CppReconciledGroup>,
) -> u32 {
    let size =
        value
            .by_name
            .iter()
            .fold(size_of::<CppReconciledGroup>(), |acc, (fq_name, index)| {
                let entry = index.rekeyed.iter().fold(0usize, |units, unit| {
                    // The vector and the provenance map retain the canonical
                    // unit twice and the physical unit once. Charge all three
                    // conservatively, even when their backing storage is shared.
                    units.saturating_add(weight_code_unit(unit).saturating_mul(3))
                });
                acc.saturating_add(fq_name.capacity())
                    .saturating_add(entry)
                    .saturating_add(size_of::<CppReconciledDefinitionIndex>())
                    .saturating_add(
                        index
                            .rekeyed
                            .capacity()
                            .saturating_mul(size_of::<CodeUnit>()),
                    )
                    .saturating_add(
                        index
                            .provisional_of
                            .capacity()
                            .saturating_mul(size_of::<(CodeUnit, CodeUnit)>() + 1),
                    )
            })
            .saturating_add(value.canonical_of.iter().fold(
                0usize,
                |size, (physical, canonical)| {
                    size.saturating_add(weight_code_unit(physical))
                        .saturating_add(weight_code_unit(canonical))
                },
            ))
            // Charge spare map slots as well as their retained unit contents.
            .saturating_add(
                value
                    .canonical_of
                    .capacity()
                    .saturating_mul(size_of::<(CodeUnit, CodeUnit)>() + 1),
            )
            .saturating_add(
                value
                    .by_name
                    .capacity()
                    .saturating_mul(size_of::<(String, Arc<CppReconciledDefinitionIndex>)>() + 1),
            )
            .saturating_add(key.member_identifier.len())
            .saturating_add(key.owner_terminal.as_ref().map_or(0, String::len));
    size.clamp(1, u32::MAX as usize) as u32
}

/// Cache admission weight for a header's C reading (#1970).
///
/// A `None` entry -- "the two readings of this blob agree" -- still costs a
/// map slot and is by far the common case, so it is charged the slot rather
/// than zero.
pub(super) fn weight_c_reading(
    _key: &ProjectFile,
    value: &Option<Arc<super::projection::CppCReading>>,
) -> u32 {
    let Some(reading) = value.as_ref() else {
        return size_of::<Option<Arc<super::projection::CppCReading>>>() as u32;
    };
    let units = reading
        .declarations
        .len()
        .saturating_add(reading.c_only.len())
        .saturating_add(reading.cpp_only.len())
        .saturating_add(reading.top_level_declarations.len())
        .saturating_add(reading.children.values().map(Vec::len).sum::<usize>())
        .saturating_add(
            reading
                .site_equivalents
                .values()
                .map(Vec::len)
                .sum::<usize>(),
        );
    let ranges = reading.ranges.values().map(Vec::len).sum::<usize>();
    units
        .saturating_mul(size_of::<CodeUnit>().saturating_add(64))
        .saturating_add(ranges.saturating_mul(size_of::<Range>()))
        .saturating_add(size_of::<super::projection::CppCReading>()) as u32
}

/// #1496: one entry is a single class-like unit's declaration strength, a
/// three-state enum. The unit key carries the strings, so weigh the key the way
/// every other unit-keyed cell here does rather than counting entries.
pub(super) fn weight_class_declaration_strength(
    key: &CodeUnit,
    _value: &CppClassDeclarationStrength,
) -> u32 {
    weight_code_unit(key).clamp(1, u32::MAX as usize) as u32
}

/// #1496: one entry is a whole file's embedded export-macro class recovery, so
/// weigh it by the classes it holds rather than counting it as one entry.
pub(super) fn weight_recovered_export_class_index(
    _key: &ProjectFile,
    value: &Arc<CppRecoveredExportClassIndex>,
) -> u32 {
    approximate_index_weight(value.approximate_size())
}

/// #1537: one entry is a whole file's recovered namespace regions, so weigh it
/// by the regions it holds rather than counting it as one entry.
pub(super) fn weight_orphaned_namespace_scopes(
    _key: &ProjectFile,
    value: &Arc<OrphanedNamespaceScopeIndex>,
) -> u32 {
    approximate_index_weight(value.approximate_size())
}

fn approximate_index_weight(size: usize) -> u32 {
    size.clamp(1, u32::MAX as usize) as u32
}

/// #1496: the attribution itself is four bits; the key's path is the entry.
pub(super) fn weight_header_language_attribution(
    key: &ProjectFile,
    _value: &super::HeaderLanguageAttribution,
) -> u32 {
    let size = size_of::<ProjectFile>()
        .saturating_add(key.root().as_os_str().len())
        .saturating_add(key.rel_path().as_os_str().len())
        .saturating_add(size_of::<super::HeaderLanguageAttribution>());
    size.clamp(1, u32::MAX as usize) as u32
}

/// #1496: one entry is a whole file's object-like field-list macro event
/// stream, so weigh it by the replacements it carries.
pub(super) fn weight_object_macro_field_events(
    _key: &ProjectFile,
    value: &Arc<Vec<brokk_bifrost_cpp::declarations::ObjectMacroFieldEvent>>,
) -> u32 {
    use brokk_bifrost_cpp::declarations::ObjectMacroFieldEvent;
    let size = value
        .iter()
        .fold(size_of::<Vec<ObjectMacroFieldEvent>>(), |acc, event| {
            let event_size = size_of::<ObjectMacroFieldEvent>();
            let content = match event {
                ObjectMacroFieldEvent::Define {
                    name, replacement, ..
                } => name
                    .len()
                    .saturating_add(weight_object_macro_replacement(replacement)),
                ObjectMacroFieldEvent::Undef { name, .. } => name.len(),
            };
            acc.saturating_add(event_size).saturating_add(content)
        });
    size.clamp(1, u32::MAX as usize) as u32
}

fn weight_object_macro_replacement(
    replacement: &brokk_bifrost_cpp::graph::syntax::ObjectMacroReplacement,
) -> usize {
    let fields = replacement.fields.iter().fold(0usize, |acc, field| {
        acc.saturating_add(size_of_val(field))
            .saturating_add(field.name.len())
            .saturating_add(field.declaration.len())
    });
    let nested = replacement
        .nested
        .iter()
        .fold(0usize, |acc, name| acc.saturating_add(name.len()));
    fields.saturating_add(nested)
}
