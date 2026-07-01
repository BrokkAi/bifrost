//! Shared vocabulary for receiver facts used by usage analysis.
//!
//! This module intentionally defines names and states, not a full fact provider.
//! Language-specific analyzers still own their AST walks. The shared vocabulary
//! keeps those analyzers honest about what they have proven, what they have not
//! proven, and which usage surfaces may consume the resulting hit.

#![allow(dead_code)]

/// How a receiver expression gets its meaning in source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverOrigin {
    /// Java/C#/C++/Scala-style `this`, Rust `self`/`Self`, or another receiver
    /// whose owner is primarily the lexically enclosing class/impl.
    LexicalEnclosingType,
    /// JavaScript `this` or Ruby `self`, where runtime call context, class/module
    /// body context, or metaprogramming can change the receiver.
    RuntimeContext,
    /// Python-style `self`/`cls`: an ordinary parameter that conventionally names
    /// the current instance/class but can be shadowed or renamed.
    OrdinaryMethodParameter,
    /// Go-style named method receiver or another language form that explicitly
    /// binds the receiver as a local name.
    NamedReceiverParameter,
    /// Imported namespace, module object, package object, CommonJS `exports`, or
    /// `module.exports`.
    ModuleOrExportObject,
    /// Class constructor, static class object, prototype object, or namespace value
    /// that can legitimately declare members through assignment.
    DeclarationWorthyObject,
    /// Ordinary local/parameter value such as `const obj = {}; obj.x = 1`; this is
    /// a value receiver, not a declaration target.
    PlainLocalValue,
}

/// Structured result of resolving a receiver expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiverResolution<T> {
    /// The analyzer has structurally proven one or more receiver targets.
    Precise(Vec<T>),
    /// Multiple incompatible targets are possible and cannot be safely narrowed.
    Ambiguous(Vec<T>),
    /// The language strategy has no structured fact for this receiver.
    Unknown,
    /// The receiver shape is outside the current model.
    Unsupported { reason: &'static str },
}

impl<T> ReceiverResolution<T> {
    pub(crate) fn is_precise(&self) -> bool {
        matches!(self, Self::Precise(_))
    }
}

/// The high-level kind of member lookup implied by a receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReceiverDispatchKind {
    Instance,
    ClassOrStatic,
    ModuleOrNamespace,
    DeclarationTarget,
}
