//! Acceptance tests for tsconfig/jsconfig `paths` alias resolution in the JS/TS
//! export-usage graph (the `scan_usages` backend): production callers that import a
//! changed symbol through a `@/`-style alias must be found, not just the test files
//! that happen to use a relative import.

mod common;

use brokk_bifrost::usages::{
    FuzzyResult, JsTsExportUsageGraphStrategy, UsageAnalyzer, UsageFinder, UsageHit,
};
use brokk_bifrost::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, JavascriptAnalyzer, Language, ProjectFile,
    TypescriptAnalyzer,
};
use common::InlineTestProject;
use std::collections::BTreeSet;

fn ts_target(analyzer: &TypescriptAnalyzer, source: &ProjectFile, name: &str) -> CodeUnit {
    analyzer
        .all_declarations()
        .find(|cu| cu.source() == source && cu.identifier() == name && cu.is_function())
        .cloned()
        .unwrap_or_else(|| panic!("target function `{name}` not found"))
}

fn flatten_hits(result: FuzzyResult) -> BTreeSet<UsageHit> {
    match result {
        FuzzyResult::Success { hits_by_overload } => hits_by_overload
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .collect(),
        other => panic!("expected Success, got {other:?}"),
    }
}

const VALIDATE_SRC: &str =
    "export function validateWebhookUrl(u: string): string {\n  return u;\n}\n";
const DELIVER_SRC: &str = "import { validateWebhookUrl } from \"@/lib/validate\";\n\nexport function deliver(u: string) {\n  return validateWebhookUrl(u);\n}\n";
const TEST_SRC: &str = "import { validateWebhookUrl } from \"./validate\";\n\ndescribe(\"validateWebhookUrl\", () => {\n  it(\"passes through\", () => {\n    validateWebhookUrl(\"https://example.com\");\n  });\n});\n";

#[test]
fn ts_path_alias_finds_aliased_prod_caller_and_relative_test_caller() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }"#,
        )
        .file("src/lib/validate.ts", VALIDATE_SRC)
        .file("src/app/deliver.ts", DELIVER_SRC)
        .file("src/lib/validate.test.ts", TEST_SRC)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let target = ts_target(
        &analyzer,
        &project.file("src/lib/validate.ts"),
        "validateWebhookUrl",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph strategy should succeed");

    let files: BTreeSet<_> = hits.iter().map(|hit| hit.file.clone()).collect();
    assert!(
        files.contains(&project.file("src/app/deliver.ts")),
        "expected the @/-aliased production caller (src/app/deliver.ts) to be found, got {files:?}"
    );
    assert!(
        files.contains(&project.file("src/lib/validate.test.ts")),
        "expected the relative test caller (src/lib/validate.test.ts) to be found, got {files:?}"
    );
}

#[test]
fn ts_path_alias_resolves_through_extends_chain() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file("tsconfig.json", r#"{ "extends": "./tsconfig.base.json" }"#)
        .file(
            "tsconfig.base.json",
            r#"{
                // base config holds the alias map; the leaf inherits it
                "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } },
            }"#,
        )
        .file("src/lib/validate.ts", VALIDATE_SRC)
        .file("src/app/deliver.ts", DELIVER_SRC)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let target = ts_target(
        &analyzer,
        &project.file("src/lib/validate.ts"),
        "validateWebhookUrl",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph strategy should succeed");

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/app/deliver.ts")),
        "expected the @/-aliased caller to resolve through the extends chain"
    );
}

#[test]
fn ts_path_alias_merges_split_baseurl_and_paths_across_extends_array() {
    // TS 5 `extends` arrays merge all parents left-to-right. Here `paths` comes from one
    // parent and `baseUrl` from another; both must survive for the alias to resolve.
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "extends": ["./tsconfig.paths.json", "./tsconfig.base.json"] }"#,
        )
        .file(
            "tsconfig.paths.json",
            r#"{ "compilerOptions": { "paths": { "@/*": ["src/*"] } } }"#,
        )
        .file(
            "tsconfig.base.json",
            r#"{ "compilerOptions": { "baseUrl": "." } }"#,
        )
        .file("src/lib/validate.ts", VALIDATE_SRC)
        .file("src/app/deliver.ts", DELIVER_SRC)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let target = ts_target(
        &analyzer,
        &project.file("src/lib/validate.ts"),
        "validateWebhookUrl",
    );
    let candidates = analyzer.get_analyzed_files().into_iter().collect();

    let hits = JsTsExportUsageGraphStrategy::new()
        .find_usages(&analyzer, std::slice::from_ref(&target), &candidates, 1000)
        .into_either()
        .expect("graph strategy should succeed");

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/app/deliver.ts")),
        "expected baseUrl and paths from different extends-array parents to both apply"
    );
}

#[test]
fn ts_import_reference_index_resolves_alias() {
    // The analyzer's import/reference graph (relevance + code map) should also link the
    // aliased importer to the definition file, not only the scan_usages export graph.
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "tsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }"#,
        )
        .file("src/lib/validate.ts", VALIDATE_SRC)
        .file("src/app/deliver.ts", DELIVER_SRC)
        .build();
    let analyzer = TypescriptAnalyzer::from_project(project.project().clone());

    let referencing = analyzer.referencing_files_of(&project.file("src/lib/validate.ts"));
    assert!(
        referencing.contains(&project.file("src/app/deliver.ts")),
        "expected aliased importer to appear in the reference index, got {referencing:?}"
    );
}

#[test]
fn js_config_alias_resolves_in_export_graph() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "jsconfig.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"] } } }"#,
        )
        .file(
            "src/lib/validate.js",
            "export function validateWebhookUrl(u) {\n  return u;\n}\n",
        )
        .file(
            "src/app/deliver.js",
            "import { validateWebhookUrl } from \"@/lib/validate\";\n\nexport function deliver(u) {\n  return validateWebhookUrl(u);\n}\n",
        )
        .build();
    let analyzer = JavascriptAnalyzer::from_project(project.project().clone());

    let target = analyzer
        .all_declarations()
        .find(|cu| {
            cu.source() == &project.file("src/lib/validate.js")
                && cu.identifier() == "validateWebhookUrl"
                && cu.is_function()
        })
        .cloned()
        .expect("target function not found");

    let hits = flatten_hits(
        UsageFinder::new().find_usages_default(&analyzer, std::slice::from_ref(&target)),
    );

    assert!(
        hits.iter()
            .any(|hit| hit.file == project.file("src/app/deliver.js")),
        "expected jsconfig @/-aliased caller (src/app/deliver.js) to be found, got {hits:?}"
    );
}
