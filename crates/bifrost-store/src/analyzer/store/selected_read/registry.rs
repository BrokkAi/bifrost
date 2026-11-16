//! Fixed aggregation: query definitions generate each language's array.
use super::queries;
use brokk_bifrost_semantic::analyzer::semantic::derivation::DerivationKindId;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryClass {
    Content,
    Selection,
    DerivationInput,
}
pub struct QueryRegistration {
    pub name: &'static str,
    pub sql: &'static str,
    pub class: QueryClass,
    pub owner: Option<DerivationKindId>,
}
pub fn queries() -> impl Iterator<Item = &'static QueryRegistration> {
    [
        queries::rust::QUERIES,
        queries::go::QUERIES,
        queries::jvm::QUERIES,
        queries::python::QUERIES,
        queries::csharp::QUERIES,
        queries::common::QUERIES,
    ]
    .into_iter()
    .flatten()
}
