//! Sequence-length sweep: find the seq at which a single embed forward exhausts
//! the visible GPU and wedges. Pin to one card with CUDA_VISIBLE_DEVICES=<uuid>.
//!
//! Embeds ONE synthetic text per step, growing its token length, printing a flushed
//! BEGIN/END around each forward. A hang leaves the last BEGIN as the wedge point;
//! watch `nvidia-smi` memory alongside to see the forward's footprint.
#[cfg(not(feature = "nlp"))]
fn main() {
    eprintln!("embed_seq_probe requires the nlp feature");
    std::process::exit(1);
}

#[cfg(feature = "nlp")]
fn main() -> Result<(), String> {
    use std::io::Write;
    use std::time::Instant;

    use brokk_bifrost::nlp::engine::load_production_embedder;

    eprintln!("[seq] loading embedder on visible GPU(s)");
    let embedder = load_production_embedder()?;

    // Build a text of roughly `target` tokens by repeating varied words (so BPE
    // produces many distinct tokens rather than one giant merge).
    let words = ["compute", "render", "buffer", "handle", "vector", "matrix", "kernel", "stream"];
    let make_text = |target: usize| -> String {
        let mut s = String::new();
        let mut i = 0usize;
        while embedder.count_tokens(&s) < target {
            s.push_str(words[i % words.len()]);
            s.push(' ');
            i += 1;
            // Re-measure only periodically to keep it cheap.
            if i.is_multiple_of(256) && embedder.count_tokens(&s) >= target {
                break;
            }
        }
        s
    };

    let stderr = std::io::stderr();
    for target in [1024usize, 2048, 3072, 4096, 5120, 6144, 7168, 8192, 8192] {
        let text = make_text(target);
        let toks = embedder.count_tokens(&text);
        {
            let mut h = stderr.lock();
            let _ = writeln!(h, "[seq] BEGIN target={target} actual_tokens={toks} bytes={}", text.len());
            let _ = h.flush();
        }
        let t = Instant::now();
        let _ = embedder.embed_passages(&[text.as_str()])?;
        eprintln!("[seq] END   target={target} tokens={toks} {}ms", t.elapsed().as_millis());
    }
    eprintln!("[seq] done — no wedge across the sweep");
    Ok(())
}
