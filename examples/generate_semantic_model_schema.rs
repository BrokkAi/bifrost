use brokk_bifrost::analyzer::semantic_model::{
    CompilerOptions, CompressionPolicy, SourceFormat, authoring_json_schema, compile_source,
};
use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = root.join("schemas/semantic-model-pack-v1.schema.json");
    std::fs::write(&output, authoring_json_schema()).expect("write generated JSON Schema");
    println!("wrote {}", output.display());

    let fixtures = root.join("tests/fixtures/semantic-model-packs");
    generate_golden(
        &fixtures,
        "declarations-v1",
        CompressionPolicy::AlwaysRaw,
        "json",
    );
    generate_golden(
        &fixtures,
        "generator-rules-v1",
        CompressionPolicy::AlwaysDeflate,
        "deflate",
    );
}

fn generate_golden(
    fixtures: &std::path::Path,
    stem: &str,
    compression: CompressionPolicy,
    shard_extension: &str,
) {
    let source = std::fs::read(fixtures.join(format!("{stem}.json"))).expect("read fixture");
    let compiled = compile_source(
        SourceFormat::Json,
        &source,
        &CompilerOptions {
            compression,
            ..CompilerOptions::default()
        },
    )
    .unwrap_or_else(|diagnostics| panic!("fixture compilation failed: {diagnostics:#?}"));
    assert_eq!(compiled.shards.len(), 1, "golden fixtures have one shard");
    std::fs::write(
        fixtures.join(format!("{stem}.manifest.json")),
        compiled.manifest_bytes,
    )
    .expect("write golden manifest");
    std::fs::write(
        fixtures.join(format!("{stem}.shard.{shard_extension}")),
        &compiled.shards[0].bytes,
    )
    .expect("write golden shard");
}
