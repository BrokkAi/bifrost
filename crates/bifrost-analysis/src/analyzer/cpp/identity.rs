//! The two downcast-owning wrappers over C++'s searchtools identity block.
//!
//! The roles, the occurrence classifier, the linkage evidence and the #1134
//! reconciliation all live in [`brokk_bifrost_cpp::identity`]; searchtools and
//! `usages/candidates.rs` reach them through the `pub(crate)` re-export block in
//! `analyzer/mod.rs`, unchanged.
//!
//! What could not cross is the *evidence root*. `cpp_header_body_files_are_related`
//! is reached through `&dyn IAnalyzer` and needs the include graph, which only
//! `CppAnalyzer` owns and no capability carries. So the predicate itself moved
//! and these two wrappers stayed, owning the `resolve_analyzer::<CppAnalyzer>`
//! downcast that produces the `CppSource` the predicate reads the closure off.
//! A non-C++ analyzer answers `false`, exactly as the downcast's `else` arm did
//! before.

use super::CppAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, resolve_analyzer};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::resolver::VisibilityIndex;

pub(crate) fn cpp_header_body_files_are_related(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    left: &ProjectFile,
    right: &ProjectFile,
) -> bool {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return false;
    };
    brokk_bifrost_cpp::identity::cpp_header_body_files_are_related(cpp, token, left, right)
}

pub(crate) fn cpp_callable_definitions_share_identity_evidence(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    brokk_bifrost_cpp::identity::cpp_callable_definitions_share_identity_evidence(
        analyzer,
        left,
        right,
        |left_source, right_source| {
            cpp_header_body_files_are_related(analyzer, token, left_source, right_source)
        },
    )
}

/// The #2010 variant, which decides the parameter lists by resolving the names
/// they spell instead of by comparing the persisted signature strings.
///
/// Definition lookup uses it; the workspace-scale scans keep the string form
/// above. Both the graph source and the dispatching analyzer are needed: the
/// resolved comparison reads the definition index and the prepared syntax
/// through the former, and the include evidence still comes from the
/// `resolve_analyzer::<CppAnalyzer>` downcast the wrapper above owns.
pub(crate) fn cpp_callable_definitions_share_identity_evidence_with_visibility(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    graph: &CppGraphSource<'_>,
    visibility: &VisibilityIndex<'_>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    brokk_bifrost_cpp::identity::cpp_callable_definitions_share_identity_evidence_with_visibility(
        graph,
        visibility,
        left,
        right,
        |left_source, right_source| {
            cpp_header_body_files_are_related(analyzer, token, left_source, right_source)
        },
    )
}
