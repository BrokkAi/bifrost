use brokk_bifrost_analysis::analyzer::semantic_model::{
    AuthoredSummaryExitKind, AuthoredSummaryInput, AuthoredSummaryOutput, AuthoredSummaryTransfer,
};

use super::ir::{FoundrySignature, FoundryTarget};

pub(super) fn target(member: &str, types: &[&str]) -> FoundryTarget {
    FoundryTarget {
        artifact_path: "java/lang/String.class".to_owned(),
        member: member.to_owned(),
        signature: FoundrySignature::Overload {
            types: types.iter().map(|value| (*value).to_owned()).collect(),
        },
    }
}

pub(super) fn transfer(input: AuthoredSummaryInput) -> AuthoredSummaryTransfer {
    AuthoredSummaryTransfer {
        input,
        exit_kind: AuthoredSummaryExitKind::Normal,
        output: AuthoredSummaryOutput::NormalReturn {},
        value_transfer: None,
    }
}
