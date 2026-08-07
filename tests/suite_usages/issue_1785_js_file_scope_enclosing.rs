//! #1785: a JS usage hit that no declaration encloses must still be reported,
//! attributed to the file's own scope.
//!
//! The JS/TS graph hit builder attributes every hit to the declaration that
//! encloses it, and used to drop the hit with `?` when there was none. That is
//! an inverse miss with no diagnostic anywhere: a structurally located
//! reference disappears and the query answers "no usages".
//!
//! Reaching that state needs a candidate file the analyzer holds no
//! declarations for, because for an *indexed* JS file something always encloses
//! a top-level reference -- the module unit when the file has imports, the
//! synthetic file-scope unit when it does not. A file with a line past
//! `DEFAULT_MAX_LINE_LENGTH` is that shape: `is_unparseable_source` rejects it,
//! so it has no `FileState` at all, while the usage scan parses it from disk
//! and finds the reference anyway. (Tree-sitter error recovery alone does *not*
//! produce this shape: a class destroyed by recovery still leaves the file's
//! module unit spanning the whole program.)
//!
//! The production path is the LSP one: `usage_hits_for_candidates_in_file`
//! hands the finder the document being edited as an explicit candidate,
//! whatever the analyzer made of it -- and a JS file with a 20k-character line
//! is an ordinary bundled or generated file. That is what this test drives.

use crate::common::InlineTestProject;
use brokk_bifrost::hash::HashSet;
use brokk_bifrost::usages::{
    DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, ExplicitCandidateProvider, FuzzyResult, UsageFinder,
    UsageHit,
};
use brokk_bifrost::{AnalyzerConfig, CodeUnit, Language, ProjectFile, SearchToolsService};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;

/// A line past `DEFAULT_MAX_LINE_LENGTH` (16_000), which is what makes the
/// analyzer refuse the whole file.
fn oversized_line() -> String {
    format!("const blob = \"{}\";\n", "x".repeat(20_000))
}

#[test]
fn reference_in_an_unindexed_file_is_reported_at_file_scope() {
    // `fs` has no known type here, so the member reference is recorded on the
    // unproven channel -- the same shape as the yarn `fs.lockQueue` sites that
    // found this bug. Proof is not the point: the hit existed either way, and
    // used to be discarded before it could be classified at all.
    let caller = format!("{}\nfs.lockQueue();\n", oversized_line());
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "a.js",
            "export class Fetcher {\n  lockQueue() {\n    return 1;\n  }\n}\n",
        )
        .file("b.js", &caller)
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let caller_file = project.file("b.js");
    assert!(
        analyzer.get_declarations(&caller_file).is_empty(),
        "the witness needs a file the analyzer holds no declarations for"
    );
    let target = analyzer
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.is_function() && unit.identifier() == "lockQueue")
        .expect("lockQueue method");

    let files: HashSet<ProjectFile> = std::iter::once(caller_file.clone()).collect();
    let provider = ExplicitCandidateProvider::new(Arc::new(files));
    let result = UsageFinder::new()
        .query_with_provider(
            analyzer,
            std::slice::from_ref(&target),
            Some(&provider),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        )
        .result;
    let FuzzyResult::Success {
        unproven_by_overload,
        ..
    } = &result
    else {
        panic!("expected Success, got {result:?}");
    };
    let hits: BTreeSet<&UsageHit> = unproven_by_overload.values().flatten().collect();

    let call_offset = caller.rfind("lockQueue").expect("member reference");
    let hit = hits
        .iter()
        .find(|hit| hit.file == caller_file && hit.start_offset == call_offset)
        .unwrap_or_else(|| {
            panic!(
                "the member reference must be reported, not dropped for want of \
                 an enclosing declaration; result: {result:#?}"
            )
        });
    assert_eq!(
        CodeUnit::file_scope(caller_file.clone()),
        hit.enclosing,
        "with no enclosing declaration the hit belongs to the file's own scope, \
         which is the same unit the analyzer synthesizes for every file it does \
         index; result: {result:#?}"
    );
}

/// The ordinary shape keeps the enclosing unit it already had: an indexed file
/// attributes a top-level call to its module unit, so the fallback above is
/// reached only when there is genuinely nothing else to attribute the hit to.
#[test]
fn top_level_call_in_an_indexed_file_keeps_its_module_enclosing() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file("a.js", "export function target() {\n  return 1;\n}\n")
        .file("b.js", "import { target } from './a.js';\n\ntarget();\n")
        .build();
    let service = SearchToolsService::new_without_semantic_index(project.root().to_path_buf())
        .expect("failed to build searchtools service over inline project");
    let payload = service
        .call_tool_json(
            "scan_usages_by_reference",
            r#"{"symbols":["target"],"include_tests":true}"#,
        )
        .expect("scan_usages_by_reference call failed");
    let value: Value =
        serde_json::from_str(&payload).expect("scan_usages_by_reference returned invalid JSON");

    assert_eq!("found", value["results"][0]["status"], "payload: {value:#}");
    let hit = &value["results"][0]["files"][0]["hits"][0];
    assert_eq!(3, hit["line"], "payload: {value:#}");
    assert_eq!("b.js", hit["enclosing"], "payload: {value:#}");
}
