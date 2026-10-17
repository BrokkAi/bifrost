/// Find the first `needle` at or after the first `anchor` in `source`.
#[allow(dead_code)]
pub fn offset_after(source: &str, anchor: &str, needle: &str) -> Option<usize> {
    let anchor_start = source.find(anchor)?;
    Some(anchor_start + source[anchor_start..].find(needle)?)
}
