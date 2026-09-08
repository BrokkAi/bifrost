//! The downcast-owning wrappers over C++'s searchtools identity block, and the
//! declaration/definition peer producer built on them (#1650).
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
//!
//! [`cpp_declaration_definition_peers`] is here for the same reason: pairing a
//! prototype with its out-of-line body reads that include evidence, and the
//! head/body label it applies is the classifier definition navigation uses.

use super::CppAnalyzer;
use crate::analyzer::structural::{DeclarationDefinitionPeer, DeclarationDefinitionPeers};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile, QueryScope, Range,
    resolve_analyzer,
};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::resolver::{VisibilityIndex, same_logical_symbol};
use brokk_bifrost_cpp::graph_support::CppSource;
use brokk_bifrost_cpp::identity::{CppOccurrenceRole, cpp_occurrence_role_for_range};

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

/// The declaration/definition peers `file` anchors (issue #1650): every
/// callable this file declares with a prototype occurrence, paired with the
/// out-of-line body that defines it and with that body occurrence's own range.
///
/// The head/body label is the one definition navigation applies at request
/// time ([`cpp_occurrence_role_for_range`], read against the file's prepared
/// syntax), so a peer row and a definition lookup cannot disagree about which
/// occurrence is the prototype. The pairing evidence is
/// [`same_logical_symbol`] plus
/// [`cpp_callable_definitions_share_identity_evidence`], the predicate the
/// workspace-scale scans already use: equal kind, structured name and
/// signature, and either one source file or external linkage on both sides
/// with the include closure relating the header to the translation unit. Two
/// like-named `static` helpers in unrelated translation units therefore stay
/// unpaired.
///
/// Two occurrences of *one* declaration -- a prototype and its body in the
/// same translation unit, which C++ keeps in one unit's range list -- yield no
/// peer: they are one identity with two physical ranges, which
/// `physical_occurrences` already answers, and a hop from an identity to
/// itself is not indirection but a cycle every traversal would have to report.
///
/// Classes are out of scope: a same-file forward declaration is not a distinct
/// occurrence, and across files a class carries no linkage evidence to pair
/// on.
pub(crate) fn cpp_declaration_definition_peers(
    cpp: &CppAnalyzer,
    file: &ProjectFile,
) -> DeclarationDefinitionPeers {
    let analyzer: &dyn IAnalyzer = cpp;
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let mut result = DeclarationDefinitionPeers::default();
    for head in analyzer.declarations(file) {
        if !head.is_callable() {
            continue;
        }
        let mut declares_head = false;
        for range in analyzer.ranges_of(&head) {
            match cpp_occurrence_role(cpp, token, &head, &range) {
                CppOccurrenceRole::DeclarationOnly => declares_head = true,
                CppOccurrenceRole::Definition => {}
                CppOccurrenceRole::Both | CppOccurrenceRole::Unknown => {
                    result.unclassified_occurrences = true;
                }
            }
        }
        if !declares_head {
            continue;
        }
        for body in analyzer.definitions_by_structured_name(head.fq(), Language::Cpp) {
            if body == head
                || !same_logical_symbol(&body, &head)
                || !cpp_callable_definitions_share_identity_evidence(analyzer, token, &head, &body)
            {
                continue;
            }
            for range in analyzer.ranges_of(&body) {
                match cpp_occurrence_role(cpp, token, &body, &range) {
                    CppOccurrenceRole::Definition => result.peers.push(DeclarationDefinitionPeer {
                        head: head.clone(),
                        body: body.clone(),
                        body_range: range,
                    }),
                    CppOccurrenceRole::DeclarationOnly => {}
                    CppOccurrenceRole::Both | CppOccurrenceRole::Unknown => {
                        result.unclassified_occurrences = true;
                    }
                }
            }
        }
    }
    // The definition lookup that produced the bodies has no defined order, and
    // a route traversal reads a file's rows in the order they arrive.
    result.peers.sort_by(|left, right| {
        (
            left.head.fq_name(),
            left.head.signature(),
            left.body.source(),
            left.body_range.start_byte,
        )
            .cmp(&(
                right.head.fq_name(),
                right.head.signature(),
                right.body.source(),
                right.body_range.start_byte,
            ))
    });
    result
}

/// Which side of the declaration/definition split the occurrence of `unit` at
/// `range` sits on. `Unknown` when the file has no prepared syntax to read the
/// shape from, which the caller reports as an unclassified occurrence rather
/// than as an absent peer.
fn cpp_occurrence_role(
    cpp: &CppAnalyzer,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    range: &Range,
) -> CppOccurrenceRole {
    let Some(prepared) = cpp.prepared_syntax(token, unit.source()) else {
        return CppOccurrenceRole::Unknown;
    };
    cpp_occurrence_role_for_range(
        &cpp.recovered_export_class_index(token, unit.source()),
        prepared.tree().root_node(),
        prepared.source(),
        unit,
        range,
    )
}
