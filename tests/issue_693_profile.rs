//! Manual profiler for GitHub issue #693's external LGTM checkout.

mod common;

use brokk_bifrost::Language;
use common::InlineTestProject;
use common::lsp_client::{LspServer, uri_for};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn large_rust_file_definition_and_hover_stay_interactive() {
    let mut main = String::from(
        "mod config;\n\nfn mono_family(cfg: &config::Config) {\n    let _ = cfg.font.mono_family.clone();\n}\n\npub struct ReviewApp;\nimpl ReviewApp {\n",
    );
    for index in 0..600 {
        main.push_str(&format!(
            "    pub fn render_row_{index}(&self) -> usize {{ {index} }}\n"
        ));
    }
    main.push_str("}\n");

    let fixture = InlineTestProject::with_language(Language::Rust)
        .file("src/main.rs", main)
        .file(
            "src/config.rs",
            "pub struct Config {\n    pub font: FontConfig,\n}\npub struct FontConfig {\n    pub mono_family: String,\n}\n",
        )
        .build();
    let mut server = LspServer::start(fixture.root());
    let main_uri = uri_for(&fixture.file("src/main.rs").abs_path());
    let config_uri = uri_for(&fixture.file("src/config.rs").abs_path());

    let started = Instant::now();
    let definition =
        server.text_document_position_response("textDocument/definition", &main_uri, 3, 17);
    let elapsed = started.elapsed();
    let locations = definition["result"]
        .as_array()
        .unwrap_or_else(|| panic!("expected definition locations, got {definition}"));
    assert!(
        locations.iter().any(|location| {
            location["uri"].as_str() == Some(config_uri.as_str())
                && location["range"]["start"]["line"].as_u64() == Some(1)
        }),
        "expected Config.font definition, got {definition}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "large-file definition took {elapsed:?}; expected under 5 seconds"
    );

    let hover = server.hover_response(&main_uri, 3, 22);
    assert!(
        hover["result"]["contents"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("pub mono_family: String")),
        "expected mono_family hover, got {hover}"
    );
    server.shutdown();
}

#[test]
#[ignore = "requires BIFROST_ISSUE_693_ROOT pointing at the LGTM PR checkout"]
fn profile_lgtm_large_rust_definition_and_hover() {
    let root = PathBuf::from(
        std::env::var_os("BIFROST_ISSUE_693_ROOT")
            .expect("BIFROST_ISSUE_693_ROOT must name the LGTM checkout"),
    );
    let started = Instant::now();
    let mut server = LspServer::start(&root);
    eprintln!(
        "issue693 initialize_ms={:.1}",
        started.elapsed().as_secs_f64() * 1000.0
    );

    let uri = uri_for(&root.join("crates/app/src/main.rs"));
    for (method, line, character) in [
        ("textDocument/definition", 42, 12),
        ("textDocument/definition", 42, 17),
        ("textDocument/hover", 42, 12),
        ("textDocument/hover", 42, 17),
    ] {
        let started = Instant::now();
        let response = server.text_document_position_response(method, &uri, line, character);
        eprintln!(
            "issue693 method={method} line={line} character={character} elapsed_ms={:.1} result={}",
            started.elapsed().as_secs_f64() * 1000.0,
            response["result"]
        );
    }

    let stderr = server.shutdown_with_stderr();
    eprintln!("{stderr}");
}
