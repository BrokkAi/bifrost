//! Compact a cache-identity lever token file in place, keeping every identity
//! it carries (#11570).
//!
//! `cargo run -p brokk-bifrost-core --example compact_lever_tokens -- <file> [--keep N]`
//! replaces all but the last `N` token lines (default 1, at least 1) with
//! one `checkpoint` line. A lever file keeps at least one token line, so the
//! identity before its last change stays computable. Run it in a pull
//! request of its own; see `.agents/docs/cache-identity-levers.md`.

use brokk_bifrost_core::lever_tokens::LeverTokens;

const USAGE: &str = "usage: compact_lever_tokens <file> [--keep N]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(USAGE)?;
    let keep = match (args.next(), args.next(), args.next()) {
        (None, None, None) => 1,
        (Some(flag), Some(count), None) if flag == "--keep" => count.parse()?,
        _ => return Err(USAGE.into()),
    };
    if keep == 0 {
        return Err("--keep must be at least 1: a lever file keeps its last token line".into());
    }
    let text = std::fs::read_to_string(&path)?;
    let tokens = LeverTokens::parse(&text)?;
    let cut = tokens.tokens().len().saturating_sub(keep);
    let compacted = tokens.compact(&text, cut);
    assert_eq!(
        LeverTokens::parse(&compacted)?.state(),
        tokens.state(),
        "compaction must keep the file's identity"
    );
    std::fs::write(&path, compacted)?;
    println!("{path}: replaced {cut} token lines with a checkpoint");
    Ok(())
}
