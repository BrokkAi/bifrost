//! Process-wide open-pack acquisition.
//!
//! Selecting the open packs can need an anonymous GitHub request, and an MCP
//! server must answer `initialize` without waiting for it (#11030). The server
//! therefore starts acquisition in the background, and each consumer waits for
//! the outcome only when it needs the packs:
//!
//! - semantic-pack registration, which the MCP session warm runs in its
//!   expensive stage while queries report the acquisition as pending;
//! - policy catalog and bundle loading, which a policy tool reaches on first
//!   use.
//!
//! One-shot CLI commands acquire before they run, so they never observe a
//! pending acquisition. Nothing here writes the pack roots into the process
//! environment: consumers read the outcome through the hooks this module
//! installs, which keeps a background thread from mutating the environment
//! while other threads read it.

use std::path::PathBuf;
use std::sync::OnceLock;

use brokk_bifrost_policy::HostPolicyRoots;
use brokk_bifrost_semantic_packs::download::{
    OpenPackFallbackKind, OpenPackRuntimeOutcome, open_pack_runtime_semantic_cache_root,
    prepare_open_packs_for_runtime,
};

pub(crate) const SEMANTIC_BUNDLE_ENV: &str = "BIFROST_OPEN_SEMANTIC_PACK_BUNDLE";

#[derive(Debug, Default)]
struct OpenPackRoots {
    semantic_bundle_root: Option<PathBuf>,
    policy: HostPolicyRoots,
}

/// Set once this process has committed to acquiring open packs.
static REQUESTED: OnceLock<()> = OnceLock::new();
static OUTCOME: OnceLock<Result<OpenPackRoots, String>> = OnceLock::new();

/// Acquire the open packs before returning, for one-shot commands. An
/// explicit-source failure is an error; a soft outcome continues without
/// packs.
pub fn acquire_open_packs() -> Result<(), String> {
    if !request_acquisition()? {
        return Ok(());
    }
    acquired_roots().map(|_| ())
}

/// Start acquiring the open packs on a background thread and return at once,
/// for servers that must answer their transport before the network does.
pub fn start_open_pack_acquisition() -> Result<(), String> {
    if !request_acquisition()? {
        return Ok(());
    }
    // The handle is not joined: consumers wait on the outcome instead. A
    // panic here is printed by the panic hook and leaves the outcome unset,
    // so the first consumer runs the acquisition again and reports its result.
    std::thread::Builder::new()
        .name("bifrost-open-pack-acquisition".to_owned())
        .spawn(|| {
            if let Err(error) = acquired_roots() {
                eprintln!("[bifrost] {error}");
            }
        })
        .map_err(|error| format!("failed to start open-pack acquisition: {error}"))?;
    Ok(())
}

/// The selected semantic bundle, waiting for a running acquisition; `None`
/// when this process acquires no open packs or selected no bundle.
pub(crate) fn semantic_bundle_root() -> Result<Option<PathBuf>, String> {
    if REQUESTED.get().is_none() {
        return Ok(None);
    }
    Ok(acquired_roots()?.semantic_bundle_root.clone())
}

/// Decide whether this process acquires open packs, and prepare it to: fix
/// the semantic catalog location and install the consumer hooks. Runs on the
/// startup thread before any server or analysis thread exists.
fn request_acquisition() -> Result<bool, String> {
    const SEMANTIC_CACHE_ROOT_ENV: &str = "BIFROST_SEMANTIC_PACK_CACHE_ROOT";

    if open_packs_disabled()
        || std::env::var_os(SEMANTIC_BUNDLE_ENV).is_some()
        || brokk_bifrost_policy::policy_pack_roots_from_env()
            .map_err(|error| error.to_string())?
            .is_some()
    {
        return Ok(false);
    }
    if REQUESTED.get().is_some() {
        return Ok(true);
    }
    // The catalog opens before the packs are known, so its location cannot
    // depend on the selection: every acquiring process uses the open-pack
    // cache catalog, whatever the network does.
    let cache_root = open_pack_runtime_semantic_cache_root()
        .map_err(|error| format!("open pack acquisition failed: {error}"))?;
    if std::env::var_os(SEMANTIC_CACHE_ROOT_ENV).is_none() {
        // SAFETY: the startup thread runs this before it starts the MCP
        // transport, any analysis, or the acquisition thread; the idle rayon
        // workers do not read the environment.
        unsafe { std::env::set_var(SEMANTIC_CACHE_ROOT_ENV, cache_root) };
    }
    brokk_bifrost_policy::install_host_policy_roots_provider(host_policy_roots)?;
    brokk_bifrost_analysis::analyzer::packs_document::install_shipped_semantic_pack_pending_probe(
        shipped_packs_pending,
    )?;
    REQUESTED
        .set(())
        .expect("only the startup thread requests open-pack acquisition");
    Ok(true)
}

fn acquired_roots() -> Result<&'static OpenPackRoots, String> {
    OUTCOME
        .get_or_init(select_open_packs)
        .as_ref()
        .map_err(Clone::clone)
}

fn select_open_packs() -> Result<OpenPackRoots, String> {
    let profile = crate::open_pack_engine_profile();
    match prepare_open_packs_for_runtime(&profile) {
        Ok(OpenPackRuntimeOutcome::Selected(selection)) => {
            debug_assert_eq!(
                open_pack_runtime_semantic_cache_root().as_ref(),
                Ok(&selection.semantic_cache_root),
                "the catalog fixed before acquisition must be the one the selection reports"
            );
            Ok(OpenPackRoots {
                semantic_bundle_root: selection.semantic_bundle_root,
                policy: HostPolicyRoots {
                    pack_root: selection.policy_pack_root,
                    bundle_root: selection.policy_bundle_root,
                },
            })
        }
        Ok(OpenPackRuntimeOutcome::Unselected { kind, message }) => {
            if should_warn_open_pack_fallback(&kind, open_packs_offline_requested()) {
                eprintln!(
                    "[bifrost] Open-pack acquisition {kind}: {message}. Continuing without \
                     semantic packs; set {SEMANTIC_BUNDLE_ENV} to an extracted packs release \
                     to use one offline."
                );
            }
            Ok(OpenPackRoots::default())
        }
        Err(error) => Err(format!("open pack acquisition failed: {error}")),
    }
}

fn host_policy_roots() -> Result<HostPolicyRoots, String> {
    Ok(acquired_roots()?.policy.clone())
}

fn shipped_packs_pending() -> Option<String> {
    (REQUESTED.get().is_some() && OUTCOME.get().is_none())
        .then(|| "open-pack release acquisition is still running".to_owned())
}

fn open_packs_disabled() -> bool {
    matches!(
        std::env::var("BIFROST_OPEN_PACKS_DISABLE").as_deref(),
        Ok("1" | "true")
    )
}

fn open_packs_offline_requested() -> bool {
    matches!(
        std::env::var("BIFROST_OPEN_PACKS_OFFLINE").as_deref(),
        Ok("1" | "true")
    ) || std::env::var("BIFROST_LAUNCHER_AUTO_INSTALL").as_deref() == Ok("0")
}

fn should_warn_open_pack_fallback(kind: &OpenPackFallbackKind, offline_requested: bool) -> bool {
    match kind {
        OpenPackFallbackKind::NetworkUnavailable => true,
        OpenPackFallbackKind::OfflineCacheMiss => !offline_requested,
        OpenPackFallbackKind::Disabled
        | OpenPackFallbackKind::NoCompatibleRelease
        | OpenPackFallbackKind::Pending
        | OpenPackFallbackKind::Unsupported => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4625: pack fallback diagnostics polluted expected quiet policy output"
    )]
    fn runtime_pack_fallback_warnings_match_the_outcome_policy() {
        use OpenPackFallbackKind as Kind;

        for kind in [
            Kind::Disabled,
            Kind::NoCompatibleRelease,
            Kind::Pending,
            Kind::Unsupported,
        ] {
            assert!(!should_warn_open_pack_fallback(&kind, false), "{kind:?}");
        }
        assert!(should_warn_open_pack_fallback(
            &Kind::NetworkUnavailable,
            false
        ));
        assert!(should_warn_open_pack_fallback(
            &Kind::OfflineCacheMiss,
            false
        ));
        assert!(!should_warn_open_pack_fallback(
            &Kind::OfflineCacheMiss,
            true
        ));
    }
}
