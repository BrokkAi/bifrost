//! Validated Rust qualified-name segments shared by facade producers and readers.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RustQualifiedPath<'a> {
    segments: Vec<&'a str>,
}

impl<'a> RustQualifiedPath<'a> {
    pub fn parse(path: &'a str) -> Option<Self> {
        let segments = path.split('.').collect::<Vec<_>>();
        (!segments.is_empty() && segments.iter().all(|segment| !segment.is_empty()))
            .then_some(Self { segments })
    }

    pub fn root(&self) -> &'a str {
        self.segments[0]
    }

    pub fn tail(&self) -> &[&'a str] {
        &self.segments[1..]
    }

    pub fn segments(&self) -> &[&'a str] {
        &self.segments
    }

    pub fn parent_and_member(&self) -> Option<(String, &'a str)> {
        (self.segments.len() > 1).then(|| {
            (
                self.segments[..self.segments.len() - 1].join("."),
                self.segments[self.segments.len() - 1],
            )
        })
    }

    #[cfg(test)]
    fn first_child(&self) -> Option<&'a str> {
        self.segments.get(1).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::RustQualifiedPath;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10258: every facade consumer uses validated path segments"
    )]
    fn qualified_segments_preserve_owner_member_and_reject_empty_parts() {
        let path = RustQualifiedPath::parse("sqlx_core.query.query").unwrap();
        assert_eq!(path.root(), "sqlx_core");
        assert_eq!(path.tail(), &["query", "query"]);
        assert_eq!(path.first_child(), Some("query"));
        assert_eq!(
            path.parent_and_member(),
            Some(("sqlx_core.query".into(), "query"))
        );
        assert!(RustQualifiedPath::parse("sqlx..query").is_none());
        assert!(RustQualifiedPath::parse("").is_none());
    }
}
