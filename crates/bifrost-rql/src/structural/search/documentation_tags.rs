// Compare language-owned documentation tags with structured declaration names.
// Attachment, parse status, name domains, and tag validity belong to callers.

use crate::analyzer::Range;

pub(super) struct NamedTag<'a> {
    pub name: Option<&'a str>,
    pub acceptable: bool,
    pub range: Option<Range>,
}

pub(super) fn missing_tag(name: &str, tags: &[NamedTag<'_>]) -> bool {
    !tags
        .iter()
        .any(|tag| tag.name == Some(name) && tag.acceptable)
}

pub(super) fn unknown_tag_ranges(tags: &[NamedTag<'_>], names: &[String]) -> Vec<Range> {
    tags.iter()
        .filter(|tag| tag_unknown(tag, names))
        .filter_map(|tag| tag.range)
        .collect()
}

pub(super) fn has_unknown_tag(tags: &[NamedTag<'_>], names: &[String]) -> bool {
    tags.iter().any(|tag| tag_unknown(tag, names))
}

fn tag_unknown(tag: &NamedTag<'_>, names: &[String]) -> bool {
    tag.name
        .is_none_or(|name| !names.iter().any(|actual| actual == name))
}
