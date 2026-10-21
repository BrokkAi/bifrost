use brokk_bifrost_core::analyzer::model::Range;

use crate::analyzer::semantic::ArgumentDomain;

pub use crate::analyzer::semantic::FormalParameterPassingMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormalParameterSlot {
    pub names: Vec<String>,
    pub declaration_range: Range,
    pub receiver: bool,
    pub variadic: Option<FormalVariadicKind>,
    pub passing_mode: FormalParameterPassingMode,
    /// The span of the default expression this parameter declares, when its
    /// grammar names one. `None` means the parameter declares no default *or*
    /// the language has none at all; see [`parameter_default_range`] for which
    /// grammars record it (issue #2499).
    pub default_range: Option<Range>,
}

impl FormalParameterSlot {
    pub fn unique_name(&self) -> Option<&str> {
        let [name] = self.names.as_slice() else {
            return None;
        };
        Some(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormalVariadicKind {
    Positional,
    Keyword,
    Both,
}

impl FormalVariadicKind {
    pub(crate) fn accepts_positional(self) -> bool {
        self.argument_domain().accepts_positional()
    }

    pub(crate) fn accepts_keyword(self) -> bool {
        matches!(self, Self::Keyword | Self::Both)
    }

    const fn argument_domain(self) -> &'static ArgumentDomain {
        match self {
            Self::Positional => &ArgumentDomain::Positional,
            Self::Keyword => &ArgumentDomain::Keyword,
            Self::Both => &ArgumentDomain::PositionalOrKeyword,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonMethodBinding {
    Instance,
    Class,
    Static,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FormalParameterLayout {
    pub slots: Vec<FormalParameterSlot>,
    pub python_binding: Option<PythonMethodBinding>,
}
