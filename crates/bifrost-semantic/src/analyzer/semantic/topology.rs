/// The build-declared scope of one dependency.
///
/// This is the shared envelope of #2442 and #2448: the same seven labels
/// describe an edge between two targets of this workspace
/// ([`TopologyEdge::kind`]) and an external package a resolver found
/// (`ResolvedDependency::scope`). One vocabulary is the point -- an
/// architecture rule that forbids a compile-scoped dependency means the same
/// thing on both sides -- and every build model this repository reads
/// expresses scope in these terms.
///
/// [`DependencyScope::Unknown`] is the default and is a real answer: a
/// resolver that cannot attribute a dependency to a scope writes it rather
/// than guessing the nearest match, and a policy concluding from scope must
/// treat it as unproven.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyScope {
    Compile,
    Runtime,
    Test,
    Provided,
    Optional,
    FeatureGated,
    #[default]
    Unknown,
}

impl DependencyScope {
    pub const LABELS: &'static [&'static str] = &[
        "compile",
        "runtime",
        "test",
        "provided",
        "optional",
        "feature_gated",
        "unknown",
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Runtime => "runtime",
            Self::Test => "test",
            Self::Provided => "provided",
            Self::Optional => "optional",
            Self::FeatureGated => "feature_gated",
            Self::Unknown => "unknown",
        }
    }
}
