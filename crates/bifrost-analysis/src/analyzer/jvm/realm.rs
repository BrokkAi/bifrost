//! The JVM source realm (#1237).
//!
//! Java, Scala, and Kotlin sources in one workspace compile to one classpath,
//! so a declaration written in any of them can be named from the other two.
//! Bifrost analyzes each language with its own analyzer, though, and those
//! analyzers only index their own files — a Kotlin analyzer asked about
//! `app.Api` has no idea a Java file next door declares it.
//!
//! [`JvmSourceRealm`] is the view that closes that gap. It is built at query
//! time from whatever analyzer is in hand and holds nothing: for a bare
//! single-language analyzer it finds one member, and for a
//! [`crate::analyzer::MultiAnalyzer`] it finds every JVM delegate the workspace
//! has.
//!
//! # Why a view and not a stored handle
//!
//! Giving each JVM analyzer a handle to its siblings would make Java, Scala,
//! and Kotlin mutually reference-counted, and every one of those cycles would
//! leak. Building the view from `&dyn IAnalyzer` per query owns nothing, cannot
//! cycle, and follows the precedent already set by the Java↔Scala usage scan.
//!
//! # What sharing a realm does and does not mean
//!
//! Realm members share a *declaration universe*: a name lookup can land on any
//! member's declarations. They do not share resolvers. A Kotlin reference is
//! still resolved by Kotlin's rules — the realm only widens what "this name
//! exists" can answer yes to, so a Kotlin class can extend a Java interface
//! without Kotlin having to understand Java's own name resolution.

use crate::analyzer::{
    CodeUnit, ForwardQueryProvider, IAnalyzer, JavaAnalyzer, KotlinAnalyzer, Language,
    ScalaAnalyzer, resolve_analyzer,
};

/// The JVM analyzers a workspace has, viewed as one declaration universe.
pub(crate) struct JvmSourceRealm<'a> {
    members: Vec<(Language, &'a dyn ForwardQueryProvider)>,
}

impl<'a> JvmSourceRealm<'a> {
    /// Every JVM analyzer reachable from `analyzer`.
    ///
    /// Works identically for a single-language analyzer and for a
    /// `MultiAnalyzer`; the caller does not have to know which it holds.
    pub(crate) fn of(analyzer: &'a dyn IAnalyzer) -> Self {
        let mut members: Vec<(Language, &'a dyn ForwardQueryProvider)> = Vec::new();
        if let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) {
            members.push((Language::Java, java));
        }
        if let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) {
            members.push((Language::Scala, scala));
        }
        if let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) {
            members.push((Language::Kotlin, kotlin));
        }
        Self { members }
    }

    /// Whether the realm has any member other than `language`.
    ///
    /// A realm of one is the same universe the language already had, so a
    /// caller can skip the wider lookup entirely.
    pub(crate) fn has_peers_of(&self, language: Language) -> bool {
        self.members.iter().any(|(member, _)| *member != language)
    }

    /// Class-like declarations named `fqn` in realm members other than
    /// `language`.
    ///
    /// The caller's own analyzer is excluded because it has already answered
    /// for itself, through its own indexes and caches, before reaching here.
    pub(crate) fn peer_types_by_fqn(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        let mut units: Vec<CodeUnit> = self
            .members
            .iter()
            .filter(|(member, _)| *member != language)
            .flat_map(|(_, provider)| provider.forward_definition_fqn(fqn))
            .filter(|unit| unit.is_class() && unit.fq_name() == fqn && !unit.is_synthetic())
            .collect();
        units.sort();
        units.dedup();
        units
    }

    /// Any declaration named `fqn` in realm members other than `language`,
    /// class-like or not.
    ///
    /// Kotlin imports reach functions and properties as well as types, so this
    /// is deliberately wider than [`Self::peer_types_by_fqn`].
    pub(crate) fn peer_declarations_by_fqn(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        let mut units: Vec<CodeUnit> = self
            .members
            .iter()
            .filter(|(member, _)| *member != language)
            .flat_map(|(_, provider)| provider.forward_definition_fqn(fqn))
            .filter(|unit| unit.fq_name() == fqn && !unit.is_synthetic())
            .collect();
        units.sort();
        units.dedup();
        units
    }
}
