//! JavaScript and JSX provider entry point for the shared JS/TS lowerer.

use crate::analyzer::JavascriptAnalyzer;
use crate::analyzer::js_ts::semantic::JsTsSemanticLowerer;
use crate::analyzer::semantic::impl_program_semantics_provider;

impl_program_semantics_provider!(JavascriptAnalyzer, JsTsSemanticLowerer::javascript());
