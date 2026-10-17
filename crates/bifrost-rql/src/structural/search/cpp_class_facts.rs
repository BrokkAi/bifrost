//! C++ source-fact qualifications for the CodeQL parity class rules.

use super::*;
use brokk_bifrost_core::analyzer::cpp_class_facts::{
    CppAccessSpecifier, CppAssignmentReturnShape, CppClassFactKind, CppClassFactRows,
    CppMemberRole, CppSpecialMemberKind, CppSpecialMemberState, CppThrowOperandShape,
};
use brokk_bifrost_core::analyzer::cpp_facts::CppDeclarationSourceFact;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

pub(super) fn cpp_class_fact_expansions(
    analyzer: &dyn IAnalyzer,
    class_cache: &mut HashMap<ProjectFile, Arc<CppClassFactRows>>,
    declaration_cache: &mut HashMap<ProjectFile, Arc<Vec<CppDeclarationSourceFact>>>,
    token: QueryToken<'_>,
    seed: &Arc<SeedMatch>,
    kind: CppClassFactKind,
) -> Vec<PipelineExpansion> {
    if seed.language != Language::Cpp {
        return Vec::new();
    }
    let class_facts = if let Some(facts) = class_cache.get(&seed.file).cloned() {
        facts
    } else {
        let Some(facts) = analyzer.cpp_class_source_facts(&seed.file) else {
            return Vec::new();
        };
        class_cache.insert(seed.file.clone(), Arc::clone(&facts));
        facts
    };
    let declarations = if let Some(declarations) = declaration_cache.get(&seed.file).cloned() {
        Some(declarations)
    } else {
        analyzer
            .cpp_class_declaration_source_facts(token, &seed.file)
            .inspect(|declarations| {
                declaration_cache.insert(seed.file.clone(), Arc::clone(declarations));
            })
    };
    let range = super::relations::seed_range(seed);
    if matches_cpp_fact(
        declarations
            .as_deref()
            .map(|declarations| declarations.as_slice()),
        &class_facts,
        range,
        kind,
    ) {
        vec![pipeline_expansion(PipelineValue::StructuralMatch(
            Arc::clone(seed),
        ))]
    } else {
        Vec::new()
    }
}

fn matches_cpp_fact(
    declarations: Option<&[CppDeclarationSourceFact]>,
    rows: &CppClassFactRows,
    range: crate::analyzer::Range,
    kind: CppClassFactKind,
) -> bool {
    match kind {
        CppClassFactKind::AssignmentDoesNotReturnThis => rows.members.iter().any(|member| {
            member.range == range
                && member.role == CppMemberRole::AssignmentOperator
                && member.assignment_return != CppAssignmentReturnShape::ReferenceToThis
        }),
        CppClassFactKind::CatchByValue => rows.catches.iter().any(|catch| {
            catch.range == range
                && catch.class_type
                && matches!(
                    catch.value_category,
                    brokk_bifrost_core::analyzer::cpp_class_facts::CppParameterValueCategory::Value
                )
        }),
        CppClassFactKind::ConstructorDelegation => rows
            .members
            .iter()
            .flat_map(|member| member.delegation_calls.iter())
            .any(|call| *call == range),
        CppClassFactKind::ConstructorUsedAsCopyConstructor => rows.members.iter().any(|member| {
            member.range == range
                && member.special_member == CppSpecialMemberKind::CopyConstructor
                && member.copy_parameter
                && member.remaining_parameters_defaulted
                && member.state != CppSpecialMemberState::Deleted
        }),
        CppClassFactKind::RuleOfThree => rows.classes.iter().any(|class| {
            class.range == range
                && special_member_mask(rows, &class.path) != 0
                && special_member_mask(rows, &class.path) != 0b111
        }),
        CppClassFactKind::RuleOfTwo => rows.classes.iter().any(|class| {
            if class.range != range {
                return false;
            }
            let (copy_constructor, copy_assignment) = copy_member_presence(rows, &class.path);
            copy_constructor != copy_assignment
        }),
        CppClassFactKind::ThrowingPointer => rows.throws.iter().any(|thrown| {
            thrown.range == range
                && thrown.operand_shape == CppThrowOperandShape::Pointer
                && !is_mfc_exception(declarations, &thrown.thrown_type)
        }),
        CppClassFactKind::UndisciplinedMultipleInheritance => rows.classes.iter().any(|class| {
            class.range == range && is_undisciplined_multiple_inheritance(declarations, rows, class)
        }),
    }
}

fn special_member_mask(rows: &CppClassFactRows, owner: &[String]) -> u8 {
    rows.members
        .iter()
        .filter(|member| {
            member.owner == owner
                && member.access != CppAccessSpecifier::Private
                && member.state != CppSpecialMemberState::Deleted
        })
        .fold(0, |mask, member| {
            mask | match member.special_member {
                CppSpecialMemberKind::Destructor => 0b001,
                CppSpecialMemberKind::CopyConstructor => 0b010,
                CppSpecialMemberKind::CopyAssignment => 0b100,
                _ => 0,
            }
        })
}

fn copy_member_presence(rows: &CppClassFactRows, owner: &[String]) -> (bool, bool) {
    let mut constructor = false;
    let mut assignment = false;
    for member in rows.members.iter().filter(|member| {
        member.owner == owner
            && member.access != CppAccessSpecifier::Private
            && member.state != CppSpecialMemberState::Deleted
    }) {
        constructor |= member.special_member == CppSpecialMemberKind::CopyConstructor;
        assignment |= member.special_member == CppSpecialMemberKind::CopyAssignment;
    }
    (constructor, assignment)
}

fn is_mfc_exception(
    declarations: Option<&[CppDeclarationSourceFact]>,
    thrown_type: &[String],
) -> bool {
    if thrown_type.last().is_some_and(|name| name == "CException") {
        return true;
    }
    let Some(declarations) = declarations else {
        return false;
    };
    let mut pending = vec![thrown_type.to_vec()];
    let mut seen: Vec<Vec<String>> = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_empty() || seen.iter().any(|candidate| candidate == &path) {
            continue;
        }
        if path.last().is_some_and(|name| name == "CException") {
            return true;
        }
        seen.push(path.clone());
        let Some(declaration) = declarations.iter().find(|fact| fact.lexical_path == path) else {
            continue;
        };
        pending.extend(declaration.bases.iter().map(|base| base.components.clone()));
    }
    false
}

fn is_undisciplined_multiple_inheritance(
    declarations: Option<&[CppDeclarationSourceFact]>,
    rows: &CppClassFactRows,
    class: &brokk_bifrost_core::analyzer::cpp_class_facts::CppClassFact,
) -> bool {
    let Some(declarations) = declarations else {
        return false;
    };
    let Some(declaration) = declarations
        .iter()
        .find(|fact| fact.lexical_path == class.path)
    else {
        return false;
    };
    declaration.bases.len() > 1
        && declaration.bases.iter().any(|base| {
            base.access == CppAccessSpecifier::Public && !base_is_interface(rows, &base.components)
        })
}

fn base_is_interface(rows: &CppClassFactRows, components: &[String]) -> bool {
    rows.classes.iter().any(|class| {
        class.is_interface && (class.path == components || class.path.ends_with(components))
    })
}
