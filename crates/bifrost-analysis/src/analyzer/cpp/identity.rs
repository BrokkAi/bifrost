//! The two downcast-owning wrappers over C++'s searchtools identity block.
//!
//! The roles, the occurrence classifier, the linkage evidence and the #1134
//! reconciliation all live in [`brokk_bifrost_cpp::identity`]; searchtools and
//! `usages/candidates.rs` reach them through the `pub(crate)` re-export block in
//! `analyzer/mod.rs`, unchanged.
//!
//! What could not cross is the *evidence root*. `cpp_header_body_files_are_related`
//! is reached through `&dyn IAnalyzer` and needs an `IncludeTargetIndex`, which
//! only `CppAnalyzer` owns and no capability carries. So the predicate itself
//! moved and these two wrappers stayed, owning the
//! `resolve_analyzer::<CppAnalyzer>` downcast and passing the include index and
//! the implementation file's `#include` lines in. A non-C++ analyzer answers
//! `false`, exactly as the downcast's `else` arm did before.

use super::CppAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, ImportAnalysisProvider, ProjectFile, resolve_analyzer};
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::resolver::VisibilityIndex;
use brokk_bifrost_cpp::identity::cpp_header_body_implementation_file;

pub(crate) fn cpp_header_body_files_are_related(
    analyzer: &dyn IAnalyzer,
    left: &ProjectFile,
    right: &ProjectFile,
) -> bool {
    let Some(implementation) = cpp_header_body_implementation_file(left, right) else {
        return false;
    };
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return false;
    };
    let imports = cpp.import_info_of(implementation);
    let import_statements: Vec<_> = imports
        .into_iter()
        .map(|import| import.raw_snippet)
        .collect();
    brokk_bifrost_cpp::identity::cpp_header_body_files_are_related(
        left,
        right,
        &import_statements,
        cpp.include_target_index(),
    )
}

pub(crate) fn cpp_callable_definitions_share_identity_evidence(
    analyzer: &dyn IAnalyzer,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    brokk_bifrost_cpp::identity::cpp_callable_definitions_share_identity_evidence(
        analyzer,
        left,
        right,
        |left_source, right_source| {
            cpp_header_body_files_are_related(analyzer, left_source, right_source)
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
            cpp_header_body_files_are_related(analyzer, left_source, right_source)
        },
    )
}
