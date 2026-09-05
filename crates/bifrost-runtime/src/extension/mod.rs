//! Stable, transport-neutral API for independent Bifrost applications.
//!
//! Types outside this module are deliberately not part of this compatibility
//! promise. Experimental operations name their stability in every response.
//!
//! Implementation state and unchecked identities are intentionally private:
//!
//! ```compile_fail
//! use brokk_bifrost_runtime::extension::ExtensionWorkspace;
//! fn analyzer(workspace: &ExtensionWorkspace) {
//!     let _ = &workspace.analyzer;
//! }
//! ```
//!
//! ```compile_fail
//! use brokk_bifrost_runtime::extension::{StableDigest, WorkspaceGeneration};
//! let digest = StableDigest::parse("0".repeat(64)).unwrap();
//! let _ = WorkspaceGeneration(digest);
//! ```
//!
//! Dense semantic IDs cannot masquerade as stable extension identities:
//!
//! ```compile_fail
//! use brokk_bifrost_runtime::analyzer::semantic::ProgramPointId;
//! use brokk_bifrost_runtime::extension::StableDigest;
//! let dense = ProgramPointId::default();
//! let _: StableDigest = dense.into();
//! ```

mod artifacts;
mod codec;
mod identity;
mod limits;
mod observation;
mod outcome;
mod relation;
mod typestate;
mod version;
mod workspace;

pub use artifacts::*;
pub use brokk_bifrost_rql::CodeQuery;
pub use codec::{
    ExtensionDecodeError, ExtensionEncodeError, ExtensionRequest, ExtensionResponse,
    decode_request_json, encode_request_json, encode_response_json,
};
pub use identity::{
    NormalizedRelativePath, SourceSpan, StableDigest, WorkspaceContentIdentity, WorkspaceGeneration,
};
pub use limits::{
    ExtensionCancellation, ExtensionLimitValues, ExtensionLimits, InvalidExtensionLimits,
};
pub use observation::*;
pub use outcome::{
    ExtensionCompletion, ExtensionDiagnostic, ExtensionOutcome, ExtensionResultMetadata,
    ExtensionTierReport, ExtensionWork,
};
pub use relation::*;
pub use typestate::*;
pub use version::{
    ApiStability, CapabilitySupport, EXTENSION_API_VERSION, ExtensionApiVersion,
    ExtensionCapabilityId, ExtensionCompatibility, ExtensionCompatibilityError,
    NegotiatedExtensionApi, PUBLISHED_OPERATIONS, PublishedOperation, negotiate_extension_api,
};
pub use workspace::{
    ExtensionCapabilityReport, ExtensionError, ExtensionPersistenceMode, ExtensionStoreReport,
    ExtensionWorkspace, ExtensionWorkspaceDescription, ExtensionWorkspaceError,
    ExtensionWorkspaceOptions, LanguageCapabilityReport, OperationCapability, StructuralRequest,
    StructuralResult,
};
