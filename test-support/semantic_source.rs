pub fn source_text(source: &str, start_byte: u32, end_byte: u32) -> &str {
    source
        .get(start_byte as usize..end_byte as usize)
        .expect("semantic source span must index its fixture")
}
