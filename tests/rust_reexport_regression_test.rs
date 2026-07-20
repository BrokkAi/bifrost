mod common;

use brokk_bifrost::usages::UsageFinder;
use brokk_bifrost::{IAnalyzer, Language, RustAnalyzer};
use common::InlineTestProject;
use std::collections::BTreeSet;

fn analyzer_with_files(files: &[(&str, &str)]) -> (common::BuiltInlineTestProject, RustAnalyzer) {
    let mut builder = InlineTestProject::with_language(Language::Rust);
    for (path, source) in files {
        builder = builder.file(path, *source);
    }
    let project = builder.build();
    let analyzer = RustAnalyzer::from_project(project.project().clone());
    (project, analyzer)
}

fn usages(analyzer: &RustAnalyzer, target_fqn: &str) -> BTreeSet<brokk_bifrost::usages::UsageHit> {
    let target = analyzer
        .get_definitions(target_fqn)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing {target_fqn}"));
    UsageFinder::new()
        .find_usages_default(analyzer, &[target])
        .into_either()
        .expect("Rust usage scan")
}

#[test]
fn inverse_rust_usages_follow_parent_module_reexport_identity() {
    let (project, analyzer) = analyzer_with_files(&[
        ("src/lib.rs", "pub mod de;\n"),
        (
            "src/de/mod.rs",
            "mod error;\nmod array;\npub use error::Error;\n",
        ),
        ("src/de/error.rs", "pub struct Error;\n"),
        (
            "src/de/array.rs",
            "use crate::de::Error;\n\npub fn convert() -> Result<(), Error> { Ok(()) }\n",
        ),
    ]);
    let hits = usages(&analyzer, "de.error.Error");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/de/array.rs") && hit.snippet.contains("Result<(), Error>")
        }),
        "canonical Error use through its parent reexport is missing: {hits:#?}"
    );
}

#[test]
fn inverse_rust_usages_follow_reexports_inside_workspace_crates() {
    let (project, analyzer) = analyzer_with_files(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/model\"]\nresolver = \"2\"\n",
        ),
        (
            "crates/model/Cargo.toml",
            "[package]\nname = \"model\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/model/src/lib.rs", "pub mod de;\n"),
        (
            "crates/model/src/de/mod.rs",
            "mod error;\nmod array;\npub use error::Error;\n",
        ),
        ("crates/model/src/de/error.rs", "pub struct Error;\n"),
        (
            "crates/model/src/de/array.rs",
            "use crate::de::Error;\n\npub fn convert() -> Result<(), Error> { Ok(()) }\n",
        ),
    ]);
    let hits = usages(&analyzer, "crates.model.src.de.error.Error");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("crates/model/src/de/array.rs")
                && hit.snippet.contains("Result<(), Error>")
        }),
        "workspace-crate reexport identity is missing: {hits:#?}"
    );
}

#[test]
fn inverse_rust_usages_follow_private_parent_import_aliases() {
    let (project, analyzer) = analyzer_with_files(&[
        ("src/lib.rs", "pub mod ser;\n"),
        (
            "src/ser/mod.rs",
            "mod document;\nmod error;\npub use error::Error;\n",
        ),
        ("src/ser/error.rs", "pub struct Error;\n"),
        ("src/ser/document/mod.rs", "use super::Error;\nmod array;\n"),
        (
            "src/ser/document/array.rs",
            "use super::Error;\n\npub fn convert() -> Result<(), Error> { Ok(()) }\n",
        ),
    ]);
    let hits = usages(&analyzer, "ser.error.Error");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("src/ser/document/array.rs")
                && hit.snippet.contains("Result<(), Error>")
        }),
        "canonical Error use through private parent aliases is missing: {hits:#?}"
    );
}

#[test]
fn inverse_rust_usages_match_reexported_type_as_scoped_owner() {
    let (project, analyzer) = analyzer_with_files(&[
        ("src/lib.rs", "pub mod lexer;\n"),
        (
            "src/lexer/mod.rs",
            r#"mod token;
pub use token::{Token, TokenKind};

pub fn lex() -> Token {
    Token::new(TokenKind::Whitespace)
}
"#,
        ),
        (
            "src/lexer/token.rs",
            r#"pub struct Token;
pub enum TokenKind { Whitespace }
impl Token { pub fn new(_kind: TokenKind) -> Self { Self } }
"#,
        ),
    ]);

    for target_fqn in ["lexer.token.Token", "lexer.token.TokenKind"] {
        let hits = usages(&analyzer, target_fqn);
        assert!(
            hits.iter().any(|hit| {
                hit.file == project.file("src/lexer/mod.rs")
                    && hit.snippet.contains("Token::new(TokenKind::Whitespace)")
            }),
            "canonical scoped-owner use is missing for {target_fqn}: {hits:#?}"
        );
    }
}

#[test]
fn inverse_rust_usages_match_self_crate_name_namespace_path() {
    let (project, analyzer) = analyzer_with_files(&[
        (
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        (
            "src/lib.rs",
            "pub mod options;\npub use options::Options;\n",
        ),
        (
            "src/options.rs",
            "pub struct Options;\nimpl Options { pub fn default() -> Self { Self } }\n",
        ),
        (
            "examples/example.rs",
            "use demo::Options;\n\nfn run() { let _ = Options::default(); }\n",
        ),
        (
            "examples/namespaced.rs",
            "use demo::options as package;\n\nfn run() { let _ = package::Options::default(); }\n",
        ),
    ]);
    let hits = usages(&analyzer, "options.Options");

    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("examples/example.rs")
                && hit.snippet.contains("Options::default")
        }),
        "canonical use through the crate-name namespace is missing: {hits:#?}"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.file == project.file("examples/namespaced.rs")
                && hit.snippet.contains("package::Options::default")
        }),
        "canonical use through an aliased crate namespace is missing: {hits:#?}"
    );
}

#[test]
fn inverse_rust_usages_do_not_cross_same_named_reexport_chains() {
    let (project, analyzer) = analyzer_with_files(&[
        (
            "src/lib.rs",
            "pub mod left;\npub mod right;\npub mod consumer;\n",
        ),
        ("src/left/mod.rs", "mod error;\npub use error::Error;\n"),
        ("src/left/error.rs", "pub struct Error;\n"),
        ("src/right/mod.rs", "mod error;\npub use error::Error;\n"),
        ("src/right/error.rs", "pub struct Error;\n"),
        (
            "src/consumer.rs",
            "use crate::right::Error;\npub fn right_only() -> Error { Error }\n",
        ),
    ]);
    let hits = usages(&analyzer, "left.error.Error");

    assert!(
        hits.iter()
            .all(|hit| hit.file != project.file("src/consumer.rs")),
        "right::Error must not be attributed to left::Error: {hits:#?}"
    );
}
