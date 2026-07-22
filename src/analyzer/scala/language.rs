use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn tree_sitter_scala() -> *const ();
}

/// The vendored tree-sitter Scala grammar.
pub(crate) const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_scala) };
