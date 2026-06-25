//! torch <-> Candle parity for the voyage-4-nano embedder.
//!
//! Loads voyageai/voyage-4-nano through bifrost's Candle path and checks the
//! embeddings match the reference produced by the SentenceTransformer (float32),
//! captured in `tests/fixtures/voyage_parity_ref.json`. This is the guard that the
//! Candle forward — bidirectional mask, the 1024->2048 head, mean-pool, 512 MRL
//! truncation + renorm — reproduces the model.
//!
//! Ignored by default: downloads (or reuses the cache of) the ~700MB model. Run:
//!
//! ```bash
//! BIFROST_NLP_MODEL_TESTS=1 cargo test --features nlp --test nlp_voyage_parity -- --ignored
//! ```
#![cfg(feature = "nlp")]

use std::collections::HashMap;

use brokk_bifrost::nlp::engine::load_production_embedder;

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    dot / (na * nb)
}

fn max_abs_diff(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).fold(0.0, f32::max)
}

#[test]
#[ignore = "downloads and runs the real voyage-4-nano model"]
fn voyage_embeddings_match_torch_reference() {
    if std::env::var("BIFROST_NLP_MODEL_TESTS").as_deref() != Ok("1") {
        eprintln!("BIFROST_NLP_MODEL_TESTS != 1; skipping voyage parity test");
        return;
    }

    let fixture = include_str!("fixtures/voyage_parity_ref.json");
    let reference: serde_json::Value = serde_json::from_str(fixture).expect("parse fixture");
    let ref_docs: HashMap<String, Vec<f32>> =
        serde_json::from_value(reference["docs"].clone()).expect("docs");
    let ref_queries: HashMap<String, Vec<f32>> =
        serde_json::from_value(reference["queries"].clone()).expect("queries");

    // f32 on CPU keeps the comparison numerically clean (the reference is f32 too).
    let embedder = load_production_embedder().expect("load voyage-4-nano via Candle");
    assert_eq!(embedder.dim(), 512, "deployment embeds at the MRL-truncated 512 dim");

    // Passages: embed_passages applies the document prompt, matching prompt_name="document".
    let doc_texts: Vec<&str> = ref_docs.keys().map(String::as_str).collect();
    let got_docs = embedder.embed_passages(&doc_texts).expect("embed passages");
    for (text, got) in doc_texts.iter().zip(&got_docs) {
        let expected = &ref_docs[*text];
        let cos = cosine(got, expected);
        let diff = max_abs_diff(got, expected);
        assert!(
            cos > 0.999 && diff < 5e-3,
            "passage parity off for {text:?}: cosine={cos}, max_abs_diff={diff}"
        );
    }

    // Queries: embed_query applies the query prompt, matching prompt_name="query".
    for (text, expected) in &ref_queries {
        let got = embedder.embed_query(text).expect("embed query");
        let cos = cosine(&got, expected);
        let diff = max_abs_diff(&got, expected);
        assert!(
            cos > 0.999 && diff < 5e-3,
            "query parity off for {text:?}: cosine={cos}, max_abs_diff={diff}"
        );
    }
}
