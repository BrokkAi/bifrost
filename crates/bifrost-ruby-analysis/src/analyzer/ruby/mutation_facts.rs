//! Workspace-wide Ruby singleton-method replacement questions (#9336).
use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
use brokk_bifrost_analysis::analyzer::workspace_authority::{
    AuthorityInputs, record_workspace_authority_read,
};
use brokk_bifrost_analysis::analyzer::{FactSubject, IAnalyzer, Language, WorkspaceFactFamily};

/// The per-file node budget the resolver gives one scan.
pub(crate) const SINGLETON_MUTATION_MAX_NODES: usize = 200_000;

pub(super) fn answer_digest(answer: bool) -> StableDigest {
    // False includes unreadable, malformed, oversized and possibly rewritten
    // files: none of those states authorizes the model's member.
    StableDigest::sha256([u8::from(answer)])
}

pub(super) fn singleton_inputs(
    owner: &str,
    member: &str,
    answer: bool,
) -> AuthorityInputs<'static> {
    AuthorityInputs::Fact {
        language: Language::Ruby,
        subject: FactSubject::NamedMember {
            owner: owner.into(),
            member: member.into(),
        },
        answer: answer_digest(answer),
    }
}

/// Whether no Ruby file in the workspace can replace the singleton method
/// `member` of the model-declared constant `owner`. `None` means `keep_going`
/// stopped the scan; a completed scan that cannot prove it returns
/// `Some(false)`, which is safe to memoize as an open answer.
pub(super) fn singleton_member_mutation_free(
    analyzer: &dyn IAnalyzer,
    owner: &str,
    member: &str,
    max_nodes: usize,
    keep_going: &dyn Fn() -> bool,
) -> Option<bool> {
    let answer = scan_sources(analyzer, owner, member, max_nodes, keep_going);
    record_workspace_authority_read(
        analyzer,
        WorkspaceFactFamily::RubySingletonMemberMutation,
        singleton_inputs(owner, member, answer.unwrap_or(false)),
    );
    answer
}

fn scan_sources(
    analyzer: &dyn IAnalyzer,
    owner: &str,
    member: &str,
    max_nodes: usize,
    keep_going: &dyn Fn() -> bool,
) -> Option<bool> {
    let Ok(files) = analyzer.project().all_files_shared() else {
        return Some(false);
    };
    for file in files.iter() {
        if !keep_going() {
            return None;
        }
        if brokk_bifrost_core::analyzer::common::language_for_file(file) != Language::Ruby {
            continue;
        }
        let Ok(source) = analyzer.project().read_source(file) else {
            return Some(false);
        };
        let Some(tree) = brokk_bifrost_ruby::declarations::parse_ruby_tree(&source) else {
            return Some(false);
        };
        if tree.root_node().has_error()
            || !crate::analyzer::usages::get_definition::ruby::ruby_file_keeps_external_singleton(
                tree.root_node(),
                &source,
                owner,
                member,
                max_nodes,
            )
        {
            return Some(false);
        }
    }
    keep_going().then_some(true)
}
