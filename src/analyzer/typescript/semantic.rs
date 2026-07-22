//! TypeScript and TSX provider entry point for the shared JS/TS lowerer.

use crate::analyzer::TypescriptAnalyzer;
use crate::analyzer::js_ts::semantic::JsTsSemanticLowerer;
use crate::analyzer::semantic::impl_program_semantics_provider;

impl_program_semantics_provider!(TypescriptAnalyzer, JsTsSemanticLowerer::typescript());
