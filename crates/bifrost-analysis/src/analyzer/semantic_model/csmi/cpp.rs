use super::model::*;
use crate::analyzer::semantic_model::{
    CppArtifactDigest, CppArtifactSelector, CppDescriptorRole, CppDigestAlgorithm,
    CppHeaderClosure, CppIdentityStability, CppLanguage, CppPortableSymbolKey,
    CppResolutionContextRef, CppSymbolDescriptor,
};

impl From<&CppArtifactSelector> for CsmiCppArtifactSelector {
    fn from(selector: &CppArtifactSelector) -> Self {
        Self {
            purl: selector.purl.clone(),
            digests: selector
                .digests
                .iter()
                .map(|digest| CsmiCppArtifactDigest {
                    algorithm: CsmiCppDigestAlgorithm::Sha256,
                    coverage: digest.coverage.clone(),
                    canonicalization: digest.canonicalization.clone(),
                    value: digest.value.clone(),
                })
                .collect(),
        }
    }
}

impl From<CsmiCppArtifactSelector> for CppArtifactSelector {
    fn from(selector: CsmiCppArtifactSelector) -> Self {
        Self {
            purl: selector.purl,
            digests: selector
                .digests
                .into_iter()
                .map(|digest| CppArtifactDigest {
                    algorithm: CppDigestAlgorithm::Sha256,
                    coverage: digest.coverage,
                    canonicalization: digest.canonicalization,
                    value: digest.value,
                })
                .collect(),
        }
    }
}

impl From<&CppArtifactSelector> for CsmiArtifactSelector {
    fn from(selector: &CppArtifactSelector) -> Self {
        Self {
            purl: selector.purl.clone(),
            version_range: None,
            digests: selector
                .digests
                .iter()
                .map(|digest| CsmiArtifactDigest {
                    algorithm: match digest.algorithm {
                        CppDigestAlgorithm::Sha256 => CsmiDigestAlgorithm::Sha256,
                    },
                    coverage: digest.coverage.clone(),
                    canonicalization: digest.canonicalization.clone(),
                    value: digest.value.clone(),
                })
                .collect(),
        }
    }
}

impl TryFrom<CsmiArtifactSelector> for CppArtifactSelector {
    type Error = super::import::CsmiImportError;

    fn try_from(selector: CsmiArtifactSelector) -> Result<Self, Self::Error> {
        let digests = selector
            .digests
            .into_iter()
            .map(|digest| {
                if digest.algorithm != CsmiDigestAlgorithm::Sha256 {
                    return Err(Self::Error::Unsupported {
                        path: "symbols.artifactSelectors.digests.algorithm".to_owned(),
                        semantic: format!(
                            "C++ portable identity requires sha-256, found {:?}",
                            digest.algorithm
                        ),
                    });
                }
                Ok(CppArtifactDigest {
                    algorithm: CppDigestAlgorithm::Sha256,
                    coverage: digest.coverage,
                    canonicalization: digest.canonicalization,
                    value: digest.value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            purl: selector.purl,
            digests,
        })
    }
}

impl TryFrom<&CppResolutionContextRef> for CsmiCppResolutionContext {
    type Error = super::export::CsmiExportError;

    fn try_from(context: &CppResolutionContextRef) -> Result<Self, Self::Error> {
        if context.vocabulary != CSMI_C_CPP_RESOLUTION_PROFILE_ID
            || context.version != CSMI_C_CPP_RESOLUTION_PROFILE_VERSION
            || context.language != CppLanguage::Cpp
            || context.header_closure != CppHeaderClosure::Complete
        {
            return Err(Self::Error::Unsupported {
                path: "cpp_portability.resolution_context".to_owned(),
                semantic: "C++ facts require the exact complete C/C++ resolution profile"
                    .to_owned(),
            });
        }
        Ok(Self {
            vocabulary: CsmiCCppResolutionVocabulary::CCppResolution,
            version: context.version.clone(),
            context_digest: context.context_digest.clone(),
            language: CsmiCppProfileLanguage::Cpp,
            header_closure: CsmiCompleteHeaderClosure::Complete,
        })
    }
}

impl From<CsmiCppResolutionContext> for CppResolutionContextRef {
    fn from(value: CsmiCppResolutionContext) -> Self {
        Self {
            vocabulary: CSMI_C_CPP_RESOLUTION_PROFILE_ID.to_owned(),
            version: value.version,
            context_digest: value.context_digest,
            language: CppLanguage::Cpp,
            header_closure: CppHeaderClosure::Complete,
        }
    }
}

impl From<&CppPortableSymbolKey> for CsmiCppSymbolKey {
    fn from(key: &CppPortableSymbolKey) -> Self {
        Self {
            artifact_selectors: key
                .artifact_selectors
                .iter()
                .map(CsmiCppArtifactSelector::from)
                .collect(),
            scheme: key.scheme.clone(),
            scheme_version: key.scheme_version.clone(),
            stability: CsmiCppIdentityStability::Portable,
            descriptors: key
                .descriptors
                .iter()
                .map(|descriptor| CsmiCppDescriptor {
                    role: match descriptor.role {
                        CppDescriptorRole::Namespace => CsmiCppDescriptorRole::Namespace,
                        CppDescriptorRole::Type => CsmiCppDescriptorRole::Type,
                        CppDescriptorRole::Callable => CsmiCppDescriptorRole::Callable,
                    },
                    name: descriptor.name.clone(),
                    disambiguator: descriptor.disambiguator.clone(),
                })
                .collect(),
        }
    }
}

impl From<&CsmiCppSymbolKey> for CppPortableSymbolKey {
    fn from(key: &CsmiCppSymbolKey) -> Self {
        Self {
            artifact_selectors: key
                .artifact_selectors
                .iter()
                .cloned()
                .map(CppArtifactSelector::from)
                .collect(),
            scheme: key.scheme.clone(),
            scheme_version: key.scheme_version.clone(),
            stability: CppIdentityStability::Portable,
            descriptors: key
                .descriptors
                .iter()
                .map(|descriptor| CppSymbolDescriptor {
                    role: match descriptor.role {
                        CsmiCppDescriptorRole::Namespace => CppDescriptorRole::Namespace,
                        CsmiCppDescriptorRole::Type => CppDescriptorRole::Type,
                        CsmiCppDescriptorRole::Callable => CppDescriptorRole::Callable,
                    },
                    name: descriptor.name.clone(),
                    disambiguator: descriptor.disambiguator.clone(),
                })
                .collect(),
        }
    }
}

pub(super) fn cpp_symbol_key_from_core(
    symbol: &CsmiSymbolDefinition,
    model_selectors: &[CsmiArtifactSelector],
) -> Result<CppPortableSymbolKey, super::import::CsmiImportError> {
    let selectors = symbol
        .artifact_selectors
        .clone()
        .unwrap_or_else(|| model_selectors.to_vec())
        .into_iter()
        .map(CppArtifactSelector::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CppPortableSymbolKey {
        artifact_selectors: selectors,
        scheme: symbol.scheme.clone(),
        scheme_version: symbol.scheme_version.clone(),
        stability: CppIdentityStability::Portable,
        descriptors: symbol
            .descriptors
            .iter()
            .map(|descriptor| {
                Ok(CppSymbolDescriptor {
                    role: match descriptor.role {
                        CsmiDescriptorRole::Namespace => CppDescriptorRole::Namespace,
                        CsmiDescriptorRole::Type => CppDescriptorRole::Type,
                        CsmiDescriptorRole::Callable => CppDescriptorRole::Callable,
                        other => {
                            return Err(super::import::CsmiImportError::Identity(format!(
                                "unsupported C++ descriptor role {other:?}"
                            )));
                        }
                    },
                    name: descriptor.name.clone().ok_or_else(|| {
                        super::import::CsmiImportError::Identity(
                            "C++ descriptor has no name".to_owned(),
                        )
                    })?,
                    disambiguator: descriptor.disambiguator.clone().ok_or_else(|| {
                        super::import::CsmiImportError::Identity(
                            "C++ descriptor has no disambiguator".to_owned(),
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(super) fn cpp_symbol_definition(id: &str, key: &CppPortableSymbolKey) -> CsmiSymbolDefinition {
    CsmiSymbolDefinition {
        id: id.to_owned(),
        artifact_selectors: Some(
            key.artifact_selectors
                .iter()
                .map(CsmiArtifactSelector::from)
                .collect(),
        ),
        scheme: key.scheme.clone(),
        scheme_version: key.scheme_version.clone(),
        stability: match key.stability {
            CppIdentityStability::Portable => CsmiStability::Portable,
        },
        descriptors: key
            .descriptors
            .iter()
            .map(|descriptor| CsmiDescriptor {
                role: match descriptor.role {
                    CppDescriptorRole::Namespace => CsmiDescriptorRole::Namespace,
                    CppDescriptorRole::Type => CsmiDescriptorRole::Type,
                    CppDescriptorRole::Callable => CsmiDescriptorRole::Callable,
                },
                name: Some(descriptor.name.clone()),
                disambiguator: Some(descriptor.disambiguator.clone()),
            })
            .collect(),
        display_name: None,
        qualified_display_name: None,
        native_signature: None,
        documentation_name: None,
        abi_name: None,
        origin: Some(CsmiSymbolOrigin::Named),
        external_identities: Vec::new(),
        provenance: Vec::new(),
        extensions: Vec::new(),
    }
}

pub(super) fn cpp_key_native_id(
    key: &CsmiCppSymbolKey,
    key_ids: &[(CppPortableSymbolKey, String)],
) -> Result<String, super::import::CsmiImportError> {
    let key = CppPortableSymbolKey::from(key);
    key_ids
        .iter()
        .find_map(|(candidate, native)| (candidate == &key).then(|| native.clone()))
        .ok_or_else(|| {
            super::import::CsmiImportError::Identity(
                "C++ symbol key is not declared by the model".to_owned(),
            )
        })
}
