//! Ruby load syntax captured once by the primary source producer.

use crate::analyzer::model::ImportInfo;
use crate::analyzer::source_facts::{SourceImportId, SourceOccurrenceId};

pub const RUBY_SOURCE_FACTS_VERSION: i64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RubyLoadKind {
    Require,
    RequireRelative,
    Load,
    Autoload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RubyLoadFact {
    pub import: SourceImportId,
    pub kind: RubyLoadKind,
    pub has_receiver: bool,
    /// Lexical class/module segments followed by the literal constant name.
    /// None retains an unsupported dynamic or missing constant argument.
    pub autoload_constant: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RubySourceFacts {
    pub loads: Vec<RubyLoadFact>,
    pub has_parse_errors: bool,
    pub runtime_boundary: Option<(SourceOccurrenceId, RubyRuntimeBoundary)>,
}

impl RubySourceFacts {
    pub fn estimated_retained_bytes(&self) -> usize {
        self.loads
            .capacity()
            .saturating_mul(std::mem::size_of::<RubyLoadFact>())
            .saturating_add(
                self.loads
                    .iter()
                    .filter_map(|fact| fact.autoload_constant.as_ref())
                    .map(|parts| {
                        parts
                            .capacity()
                            .saturating_mul(std::mem::size_of::<String>())
                            .saturating_add(parts.iter().map(String::capacity).sum::<usize>())
                    })
                    .sum::<usize>(),
            )
    }
}

/// A mounted read projection of canonical load and import rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RubyLoadInfo {
    pub import: ImportInfo,
    pub kind: RubyLoadKind,
    pub has_receiver: bool,
    pub autoload_constant: Option<Vec<String>>,
    /// Membership in the existing declaration-oriented generic import surface.
    pub generic: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RubyRuntimeBoundary {
    ConstGet,
    ConstSet,
    RemoveConst,
    ConstMissingCall,
    ClassEval,
    ModuleEval,
    Eval,
    Autoload,
    DynamicRequire,
    DynamicRequireRelative,
    DynamicLoad,
    DynamicConstMissingDefinition,
    ConstMissingDefinition,
}

impl RubyRuntimeBoundary {
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::ConstGet,
            1 => Self::ConstSet,
            2 => Self::RemoveConst,
            3 => Self::ConstMissingCall,
            4 => Self::ClassEval,
            5 => Self::ModuleEval,
            6 => Self::Eval,
            7 => Self::Autoload,
            8 => Self::DynamicRequire,
            9 => Self::DynamicRequireRelative,
            10 => Self::DynamicLoad,
            11 => Self::DynamicConstMissingDefinition,
            12 => Self::ConstMissingDefinition,
            _ => return None,
        })
    }
    pub fn detail(self) -> String {
        match self {
            Self::Autoload => "`autoload` defers a constant to a run-time load".to_owned(),
            Self::DynamicConstMissingDefinition => {
                "`const_missing` is defined dynamically".to_owned()
            }
            Self::ConstMissingDefinition => "`const_missing` is defined in this file".to_owned(),
            Self::DynamicRequire | Self::DynamicRequireRelative | Self::DynamicLoad => {
                let name = match self {
                    Self::DynamicRequire => "require",
                    Self::DynamicRequireRelative => "require_relative",
                    _ => "load",
                };
                format!("`{name}` takes an argument this pass cannot resolve statically")
            }
            _ => {
                let name = match self {
                    Self::ConstGet => "const_get",
                    Self::ConstSet => "const_set",
                    Self::RemoveConst => "remove_const",
                    Self::ConstMissingCall => "const_missing",
                    Self::ClassEval => "class_eval",
                    Self::ModuleEval => "module_eval",
                    Self::Eval => "eval",
                    _ => unreachable!(),
                };
                format!("`{name}` can define or read a constant at run time")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RubyFileSourceInfo {
    pub loads: Vec<RubyLoadInfo>,
    pub source_bytes: usize,
    pub has_parse_errors: bool,
    pub runtime_boundary: Option<RubyRuntimeBoundary>,
}
