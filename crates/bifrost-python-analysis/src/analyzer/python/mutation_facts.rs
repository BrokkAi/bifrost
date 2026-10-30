//! Precise workspace-wide Python member replacement questions.
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, record_workspace_authority_read,
};
use brokk_bifrost_analysis::analyzer::{
    FactSubject, IAnalyzer, Language, ProjectFile, WorkspaceFactFamily,
};

pub(super) fn answer_digest(answer: bool) -> StableDigest {
    // False includes unreadable, malformed, truncated and possibly replaced
    // members: none of those states authorizes the original member value.
    StableDigest::sha256([u8::from(answer)])
}

pub(super) fn module_inputs(module: &str, member: &str, answer: bool) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: Language::Python,
        subject: FactSubject::NamedMember {
            owner: module.into(),
            member: member.into(),
        },
        answer: answer_digest(answer),
    }
}

pub(super) fn module_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    module: &str,
    member: &str,
    max_nodes: usize,
    keep_going: &dyn Fn() -> bool,
) -> Option<bool> {
    let answer = scan_sources(analyzer, keep_going, |file, root, source| {
        let source_module =
            brokk_bifrost_python::declarations::python_module_name(analyzer.project(), file);
        brokk_bifrost_python::runtime_values::python_module_member_mutation(
            root,
            source,
            &source_module,
            module,
            member,
            max_nodes,
        )
        .is_none()
    });
    record_workspace_authority_read(
        analyzer,
        WorkspaceFactFamily::PythonModuleMemberMutation,
        module_inputs(module, member, answer.unwrap_or(false)),
    );
    answer
}

pub(super) fn class_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    names: &[Box<str>],
    member: &str,
) -> bool {
    let identities = names.iter().map(AsRef::as_ref).collect::<Vec<_>>();
    class_groups_mutation_free(analyzer, &[identities], member)
}

/// Preserve the aggregate scan's file-first traversal. A replacement witness
/// proves one group's negative answer immediately; success proves all groups.
/// The aggregate memo replays exactly those sufficient group certificates.
pub(super) fn class_groups_mutation_free(
    analyzer: &dyn IAnalyzer,
    groups: &[Vec<&str>],
    member: &str,
) -> bool {
    assert!(
        !groups.is_empty(),
        "external classes supply an identity group"
    );
    let mut failed_group = None;
    let answer = scan_sources(analyzer, &|| true, |_, root, source| {
        for (index, identities) in groups.iter().enumerate() {
            if brokk_bifrost_python::runtime_values::python_external_class_member_mutation(
                root, source, identities, member, 65_536,
            )
            .is_some()
            {
                failed_group = Some(index);
                return false;
            }
        }
        true
    })
    .expect("uncancelled class scan");
    // An unreadable/malformed file makes every group unavailable, so the first
    // group is a sufficient negative certificate even without a write witness.
    let failed_group = failed_group.unwrap_or(0);
    for (index, group) in groups.iter().enumerate() {
        if answer || index == failed_group {
            let mut names = group
                .iter()
                .map(|name| Box::<str>::from(*name))
                .collect::<Vec<_>>();
            names.sort_unstable();
            names.dedup();
            record_workspace_authority_read(
                analyzer,
                WorkspaceFactFamily::PythonClassMemberMutation,
                AuthorityInputs::Fact {
                    language: Language::Python,
                    subject: FactSubject::name_group_member(names, member.into()),
                    answer: answer_digest(answer),
                },
            );
        }
    }
    answer
}

/// Both questions use the same parser-owned, bounded syntax interpretation.
fn scan_sources(
    analyzer: &dyn IAnalyzer,
    keep_going: &dyn Fn() -> bool,
    mut unmodified: impl FnMut(&ProjectFile, tree_sitter::Node<'_>, &str) -> bool,
) -> Option<bool> {
    let Ok(files) = analyzer.project().all_files_shared() else {
        return Some(false);
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("Python grammar is compatible with the parser");
    for file in files.iter() {
        if !keep_going() {
            return None;
        }
        if brokk_bifrost_core::analyzer::common::language_for_file(file) != Language::Python {
            continue;
        }
        let Ok(source) = file.read_to_string() else {
            return Some(false);
        };
        let Some(tree) = parser.parse(&source, None) else {
            return Some(false);
        };
        if tree.root_node().has_error() || !unmodified(file, tree.root_node(), &source) {
            return Some(false);
        }
    }
    keep_going().then_some(true)
}

#[cfg(test)]
mod tests;
