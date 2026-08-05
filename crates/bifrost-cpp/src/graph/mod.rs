//! The C++ usage graph's language knowledge.
//!
//! The forward scan (`extractor`), the visibility/macro/include resolver
//! (`resolver`) and the whole-workspace inverted scan (`inverted`) are one body
//! of code and cross together in the second C++ pass; what is here now is the
//! part of it that needs nothing but the grammar.

pub mod syntax;
