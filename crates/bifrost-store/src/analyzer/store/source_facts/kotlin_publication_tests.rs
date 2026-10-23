#[cfg(not(test))]
use crate::analyzer::Language;

#[cfg(not(test))]
use crate::analyzer::store::AnalyzerStore;

#[cfg(not(test))]
use crate::analyzer::store::test_support::{oid_for, parse_state};
#[cfg(not(test))]
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

#[cfg(not(test))]
use crate::analyzer::store::structural_vocabulary::STRUCTURAL_FACTS_VERSION;
#[cfg(not(test))]
use crate::analyzer::structural::facts::FileFacts;

#[cfg(not(test))]
use crate::analyzer::structural::kinds::NormalizedKind;

#[cfg(not(test))]
use crate::inline_project::InlineTestProject;

#[cfg(not(test))]
use brokk_bifrost_core::analyzer::structural::code::VocabularyCode;
