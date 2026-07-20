//! Domain-separated SHA-256 identities for loaded policy meaning.

use std::fmt;
use std::str::FromStr;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::canonical_loaded;
use super::definition::{
    CategoryPredicate, DirectoryScope, EndpointRole, MatchSetManifestHash, PolicyDefinition,
    Sha256ValueError, TaintCatalogHash,
};
use super::resolved::{
    EndpointDefinitionSchemaResolution, LoadedModelError, PolicyPrecedenceManifest,
    ResolvedCatalogIdentity, ResolvedEndpointDependency, ResolvedEndpointIdentity,
    ResolvedEndpointManifestEntry, ResolvedEndpointModel, ResolvedMatchDirectoryManifest,
    ResolvedPolicySelector, ResolvedTaintPolicySpec, ResolvedTypestatePolicySpec,
};

const POLICY_SOURCE_DOMAIN: &[u8] = b"bifrost-policy-source/v1";
const SELECTOR_SEMANTIC_DOMAIN: &[u8] = b"bifrost-policy-selector/v1";
const ENDPOINT_SEMANTIC_DOMAIN: &[u8] = b"bifrost-policy-endpoint/v1";
const ENDPOINT_ANALYSIS_DOMAIN: &[u8] = b"bifrost-policy-endpoint-analysis/v1";
const POLICY_SEMANTIC_DOMAIN: &[u8] = b"bifrost-policy-semantic/v1";
const CATALOG_SEMANTIC_DOMAIN: &[u8] = b"bifrost-policy-catalog/v1";
const MATCH_SET_DOMAIN: &[u8] = b"bifrost-policy-match-set/v1";
const TYPESTATE_AUTHORING_DOMAIN: &[u8] = b"bifrost-policy-typestate-authoring/v1";

macro_rules! define_sha256_identity {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub fn from_lower_hex(value: &str) -> Result<Self, Sha256ValueError> {
                parse_lower_sha256(value).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = Sha256ValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::from_lower_hex(value)
            }
        }
    };
}

define_sha256_identity!(PolicySourceHash);
define_sha256_identity!(ResolvedSelectorSemanticHash);
define_sha256_identity!(EndpointSemanticHash);
define_sha256_identity!(EndpointAnalysisProjectionHash);
define_sha256_identity!(TypestateAuthoringProjectionHash);

/// Semantic identity minted only by validated [`super::resolved::LoadedPolicy`]
/// construction. Unlike wire-level evidence hashes, this type intentionally
/// has no public byte/hex constructor or parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicySemanticHash([u8; 32]);

impl PolicySemanticHash {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PolicySemanticHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl PolicySourceHash {
    /// Hash exact source bytes. Comments, whitespace, and version-pin spelling
    /// are intentionally source identity.
    pub fn from_source_bytes(source: &[u8]) -> Self {
        Self(hash_fields(POLICY_SOURCE_DOMAIN, [source]))
    }
}

impl ResolvedSelectorSemanticHash {
    pub(crate) fn from_query(
        schema_version: u32,
        query: &crate::analyzer::structural::CodeQuery,
    ) -> Self {
        let value = json!({
            "schema_version": schema_version,
            "query": query.to_canonical_query_plan_json(),
        });
        Self(hash_canonical_value(SELECTOR_SEMANTIC_DOMAIN, &value))
    }
}

impl EndpointSemanticHash {
    pub(crate) fn from_loaded_endpoint(
        definition: &super::definition::MatchEndpointDefinition,
        selector: &ResolvedPolicySelector,
    ) -> Result<Self, LoadedModelError> {
        let value = canonical_loaded::loaded_endpoint_semantic_to_json(definition, selector)?;
        Ok(Self(hash_canonical_value(ENDPOINT_SEMANTIC_DOMAIN, &value)))
    }

    pub(crate) fn from_composed_endpoint(
        identity: &ResolvedEndpointIdentity,
        definition_schema: &EndpointDefinitionSchemaResolution,
        selector: &ResolvedPolicySelector,
        model: &ResolvedEndpointModel,
    ) -> Self {
        let value = canonical_loaded::composed_endpoint_semantic_to_json(
            identity,
            definition_schema,
            selector,
            model,
        );
        Self(hash_canonical_value(ENDPOINT_SEMANTIC_DOMAIN, &value))
    }
}

impl EndpointAnalysisProjectionHash {
    pub(crate) fn from_loaded_endpoint(
        definition: &super::definition::MatchEndpointDefinition,
        selector: &ResolvedPolicySelector,
    ) -> Result<Self, LoadedModelError> {
        let value =
            canonical_loaded::loaded_endpoint_analysis_projection_to_json(definition, selector)?;
        Ok(Self(hash_canonical_value(ENDPOINT_ANALYSIS_DOMAIN, &value)))
    }

    pub(crate) fn from_composed_endpoint(
        definition_schema: &EndpointDefinitionSchemaResolution,
        selector: &ResolvedPolicySelector,
        model: &ResolvedEndpointModel,
    ) -> Self {
        let value = canonical_loaded::composed_endpoint_analysis_projection_to_json(
            definition_schema,
            selector,
            model,
        );
        Self(hash_canonical_value(ENDPOINT_ANALYSIS_DOMAIN, &value))
    }
}

impl PolicySemanticHash {
    /// Constructed only as part of [`super::resolved::LoadedPolicy`] validation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_resolved_policy(
        definition: &PolicyDefinition,
        analysis: ResolvedPolicyAnalysisRef<'_>,
        selectors: &[ResolvedPolicySelector],
        catalogs: &[ResolvedCatalogIdentity],
        endpoints: &[ResolvedEndpointDependency],
        match_manifests: &[ResolvedMatchDirectoryManifest],
        precedence: &PolicyPrecedenceManifest,
    ) -> Result<Self, LoadedModelError> {
        let value = canonical_loaded::resolved_policy_to_json(
            definition,
            analysis,
            selectors,
            catalogs,
            endpoints,
            match_manifests,
            precedence,
        )?;
        Ok(Self(hash_canonical_value(POLICY_SEMANTIC_DOMAIN, &value)))
    }
}

impl TypestateAuthoringProjectionHash {
    pub(crate) fn from_spec(spec: &ResolvedTypestatePolicySpec) -> Result<Self, LoadedModelError> {
        let value = canonical_loaded::resolved_typestate_to_json(spec)?;
        Ok(Self(hash_canonical_value(
            TYPESTATE_AUTHORING_DOMAIN,
            &value,
        )))
    }
}

impl TaintCatalogHash {
    /// Hash canonical typed catalog JSON, never the registration byte layout.
    pub(crate) fn from_canonical_catalog_value(value: &Value) -> Self {
        Self::from_bytes(hash_canonical_value(CATALOG_SEMANTIC_DOMAIN, value))
    }
}

impl MatchSetManifestHash {
    pub(crate) fn from_resolved_selection(
        scope: DirectoryScope,
        role: Option<EndpointRole>,
        categories: &CategoryPredicate,
        selected: &[ResolvedEndpointManifestEntry],
    ) -> Self {
        let value =
            canonical_loaded::match_set_hash_projection_to_json(scope, role, categories, selected);
        Self::from_bytes(hash_canonical_value(MATCH_SET_DOMAIN, &value))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResolvedPolicyAnalysisRef<'a> {
    Match,
    Taint {
        spec: &'a ResolvedTaintPolicySpec,
    },
    Typestate {
        spec: &'a ResolvedTypestatePolicySpec,
    },
}

/// SHA-256 over a domain plus an ordered sequence of independently
/// length-prefixed fields. No caller can introduce delimiter ambiguity.
fn hash_fields<'a>(domain: &[u8], fields: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, domain);
    for field in fields {
        update_length_prefixed(&mut hasher, field);
    }
    hasher.finalize().into()
}

fn hash_canonical_value(domain: &[u8], value: &Value) -> [u8; 32] {
    let bytes = serde_json::to_vec(value).expect("serde_json::Value serialization is infallible");
    hash_fields(domain, [bytes.as_slice()])
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("usize fits in u64 on supported targets");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn parse_lower_sha256(value: &str) -> Result<[u8; 32], Sha256ValueError> {
    if value.len() != 64 {
        return Err(Sha256ValueError::InvalidLength);
    }
    let bytes = value.as_bytes();
    let mut digest = [0_u8; 32];
    let mut index = 0;
    while index < bytes.len() {
        digest[index / 2] = (lower_hex_nibble(bytes[index], index)? << 4)
            | lower_hex_nibble(bytes[index + 1], index + 1)?;
        index += 2;
    }
    Ok(digest)
}

fn lower_hex_nibble(byte: u8, index: usize) -> Result<u8, Sha256ValueError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(Sha256ValueError::Uppercase),
        _ => Err(Sha256ValueError::InvalidCharacter { index }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::policy::{
        CategoryPredicate, EndpointDefinitionSchemaResolution, EndpointOrigin, EndpointRole,
        LoadedEndpoint, LoadedPolicy, MatchEndpointDefinition, PolicyDependencyPath,
        PolicyEndpointBinding, PolicyPrecedenceManifest, PolicySelector, PolicySelectorPath,
        PolicySourceIdentity, ResolvedEndpointDependency, ResolvedEndpointIdentity,
        ResolvedEndpointManifestEntry, ResolvedEndpointModel, ResolvedMatchDirectoryManifest,
        ResolvedPolicySelector, RqlpDocument, SelectorOrigin, parse_rqlp_source,
    };
    use crate::analyzer::semantic::WorkspaceRelativePath;

    #[test]
    fn hash_domains_are_distinct_for_equal_bytes() {
        let bytes = b"same bytes";
        let source = PolicySourceHash::from_source_bytes(bytes);
        let endpoint =
            EndpointSemanticHash(hash_fields(ENDPOINT_SEMANTIC_DOMAIN, [bytes.as_slice()]));
        let projection = EndpointAnalysisProjectionHash(hash_fields(
            ENDPOINT_ANALYSIS_DOMAIN,
            [bytes.as_slice()],
        ));

        assert_ne!(source.as_bytes(), endpoint.as_bytes());
        assert_ne!(endpoint.as_bytes(), projection.as_bytes());
    }

    #[test]
    fn source_hash_covers_comments_and_layout() {
        let compact = PolicySourceHash::from_source_bytes(b"(policy :id \"x\")");
        let commented = PolicySourceHash::from_source_bytes(b"(policy\n  ; note\n  :id \"x\")");
        assert_ne!(compact, commented);
    }

    #[test]
    fn source_layout_and_version_origin_do_not_change_loaded_policy_semantics() {
        let implicit = include_str!("../../../tests/fixtures/policies/dynamic-eval.rqlp");
        let commented = implicit.replacen(
            "(policy",
            "(policy\n  ; an origin-only comment and different layout",
            1,
        );
        let explicit = implicit.replacen("(policy", "(policy\n  :schema-version 1", 1);

        let implicit = load_match_policy(implicit);
        let commented = load_match_policy(&commented);
        let explicit = load_match_policy(&explicit);

        assert_ne!(implicit.source_hash(), commented.source_hash());
        assert_ne!(implicit.source_hash(), explicit.source_hash());
        assert_eq!(implicit.semantic_hash(), commented.semantic_hash());
        assert_eq!(implicit.semantic_hash(), explicit.semantic_hash());
    }

    #[test]
    fn endpoint_display_changes_only_the_full_semantic_hash() {
        let source =
            include_str!("../../../tests/fixtures/policies/endpoints/http-request-parameter.rqlp");
        let renamed = source.replace("User-controlled I/O", "External request input");

        let original = load_endpoint(source);
        let renamed = load_endpoint(&renamed);

        assert_ne!(original.semantic_hash(), renamed.semantic_hash());
        assert_eq!(
            original.analysis_projection_hash(),
            renamed.analysis_projection_hash()
        );
    }

    #[test]
    fn selected_dependency_content_changes_policy_hash() {
        let policy = load_match_policy(include_str!(
            "../../../tests/fixtures/policies/dynamic-eval.rqlp"
        ));
        let selector = policy.resolved_selectors()[0].clone();
        let dependency_a = dependency_with_revision(1, selector.clone());
        let dependency_b = dependency_with_revision(2, selector.clone());

        let hash_a = PolicySemanticHash::from_resolved_policy(
            policy.definition(),
            ResolvedPolicyAnalysisRef::Match,
            std::slice::from_ref(&selector),
            &[],
            &[dependency_a],
            &[],
            &PolicyPrecedenceManifest::default(),
        )
        .unwrap();
        let hash_b = PolicySemanticHash::from_resolved_policy(
            policy.definition(),
            ResolvedPolicyAnalysisRef::Match,
            std::slice::from_ref(&selector),
            &[],
            &[dependency_b],
            &[],
            &PolicyPrecedenceManifest::default(),
        )
        .unwrap();

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn overlapping_manifest_origins_are_semantically_idempotent() {
        let policy = load_match_policy(include_str!(
            "../../../tests/fixtures/policies/dynamic-eval.rqlp"
        ));
        let categories = CategoryPredicate::Any {
            categories: vec!["input.user-controlled".parse().unwrap()],
        };
        let first = ResolvedMatchDirectoryManifest::try_new(
            PolicyDependencyPath::new("/dependencies/match-directories/first").unwrap(),
            WorkspaceRelativePath::new("policies/first").unwrap(),
            crate::analyzer::policy::DirectoryScope::Recursive,
            Some(EndpointRole::Source),
            categories.clone(),
            Vec::new(),
        )
        .unwrap();
        let second = ResolvedMatchDirectoryManifest::try_new(
            PolicyDependencyPath::new("/dependencies/match-directories/second").unwrap(),
            WorkspaceRelativePath::new("policies/second").unwrap(),
            crate::analyzer::policy::DirectoryScope::Recursive,
            Some(EndpointRole::Source),
            categories,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(first.semantic_hash, second.semantic_hash);

        let one = PolicySemanticHash::from_resolved_policy(
            policy.definition(),
            ResolvedPolicyAnalysisRef::Match,
            policy.resolved_selectors(),
            &[],
            &[],
            std::slice::from_ref(&first),
            &PolicyPrecedenceManifest::default(),
        )
        .unwrap();
        let overlapping = PolicySemanticHash::from_resolved_policy(
            policy.definition(),
            ResolvedPolicyAnalysisRef::Match,
            policy.resolved_selectors(),
            &[],
            &[],
            &[first, second],
            &PolicyPrecedenceManifest::default(),
        )
        .unwrap();

        assert_eq!(one, overlapping);
    }

    #[test]
    fn match_set_hash_excludes_richer_manifest_provenance() {
        let identity = ResolvedEndpointIdentity::MatchEndpoint {
            endpoint_id: "example-source".parse().unwrap(),
        };
        let semantic_hash = EndpointSemanticHash::from_bytes([7; 32]);
        let first = ResolvedEndpointManifestEntry {
            identity: identity.clone(),
            definition_schema: EndpointDefinitionSchemaResolution::PolicyDocument {
                resolution: crate::schema_version::SchemaVersionResolution {
                    version: 1,
                    origin: crate::schema_version::SchemaVersionOrigin::Explicit,
                },
            },
            selector_schema: crate::schema_version::SchemaVersionResolution {
                version: 2,
                origin: crate::schema_version::SchemaVersionOrigin::Explicit,
            },
            semantic_hash,
            analysis_projection_hash: EndpointAnalysisProjectionHash::from_bytes([1; 32]),
        };
        let second = ResolvedEndpointManifestEntry {
            identity,
            definition_schema: EndpointDefinitionSchemaResolution::CatalogDocument {
                schema_version: 99,
            },
            selector_schema: crate::schema_version::SchemaVersionResolution {
                version: 77,
                origin: crate::schema_version::SchemaVersionOrigin::ImplicitCompatible,
            },
            semantic_hash,
            analysis_projection_hash: EndpointAnalysisProjectionHash::from_bytes([2; 32]),
        };
        let categories = CategoryPredicate::Any {
            categories: vec!["input.user-controlled".parse().unwrap()],
        };

        assert_eq!(
            MatchSetManifestHash::from_resolved_selection(
                crate::analyzer::policy::DirectoryScope::Recursive,
                Some(EndpointRole::Source),
                &categories,
                &[first],
            ),
            MatchSetManifestHash::from_resolved_selection(
                crate::analyzer::policy::DirectoryScope::Recursive,
                Some(EndpointRole::Source),
                &categories,
                &[second],
            ),
        );
    }

    fn load_match_policy(source: &str) -> LoadedPolicy {
        let identity = PolicySourceIdentity::new("policy.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let schema_resolution = parsed.schema_resolution();
        let RqlpDocument::Policy { definition } = parsed.into_document() else {
            panic!("fixture must be a policy");
        };
        let definition = *definition;
        let crate::analyzer::policy::PolicyAnalysis::Match { spec } = &definition.analysis else {
            panic!("fixture must be a match policy");
        };
        let PolicySelector::Inline { schema, query } = &spec.selector else {
            panic!("fixture selector must be inline");
        };
        let selector = ResolvedPolicySelector::try_new(
            PolicySelectorPath::new("/analysis/selector").unwrap(),
            *schema,
            query.clone(),
            SelectorOrigin::Document {
                source: identity.clone(),
            },
        )
        .unwrap();
        LoadedPolicy::try_new(
            definition,
            identity,
            source.as_bytes(),
            schema_resolution,
            vec![selector],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PolicyPrecedenceManifest::default(),
            None,
            None,
        )
        .unwrap()
    }

    fn load_endpoint(source: &str) -> LoadedEndpoint {
        let identity = PolicySourceIdentity::new("endpoint.rqlp");
        let parsed = parse_rqlp_source(source, identity.clone()).unwrap();
        let schema_resolution = parsed.schema_resolution();
        let RqlpDocument::Endpoint { definition } = parsed.into_document() else {
            panic!("fixture must be an endpoint");
        };
        let definition: MatchEndpointDefinition = *definition;
        let PolicySelector::Inline { schema, query } = &definition.selector else {
            panic!("fixture selector must be inline");
        };
        let selector = ResolvedPolicySelector::try_new(
            PolicySelectorPath::new("/endpoint/selector").unwrap(),
            *schema,
            query.clone(),
            SelectorOrigin::Document {
                source: identity.clone(),
            },
        )
        .unwrap();
        LoadedEndpoint::try_new(
            definition,
            identity,
            source.as_bytes(),
            schema_resolution,
            selector,
        )
        .unwrap()
    }

    fn dependency_with_revision(
        revision: u32,
        selector: ResolvedPolicySelector,
    ) -> ResolvedEndpointDependency {
        let definition_schema = EndpointDefinitionSchemaResolution::PolicyDocument {
            resolution: crate::schema_version::SchemaVersionResolution {
                version: 1,
                origin: crate::schema_version::SchemaVersionOrigin::Explicit,
            },
        };
        let model = ResolvedEndpointModel::new(
            EndpointRole::Source,
            format!("Example revision {revision}"),
            Vec::new(),
            PolicyEndpointBinding::ReturnValue,
            None,
            Vec::new(),
        );
        ResolvedEndpointDependency::from_composed_model(
            ResolvedEndpointIdentity::Local {
                policy_id: "bifrost.security.dynamic-eval".parse().unwrap(),
                entry_id: "example".parse().unwrap(),
            },
            definition_schema,
            &selector,
            model,
            vec![EndpointOrigin::PolicyLocal {
                path: PolicyDependencyPath::new("/dependencies/example").unwrap(),
            }],
        )
        .unwrap()
    }
}
