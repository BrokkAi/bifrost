use super::*;
use schemars::JsonSchema;

/// One compilation input set the build declares, as a query row (#2448).
///
/// The row is reached from a file through `source_set_of`, so its existence is
/// itself the statement "the build says this file compiles here". A file no
/// build file claims produces no row and an explicit diagnostic; it never
/// produces a row derived from the file's path.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQuerySourceSet {
    /// The source set's stable identity: a digest over the coordinates the
    /// build declares for it, never over the build files that justify it.
    pub id: String,
    /// The name the build declares, unique within its kind (`domain:test`).
    pub name: String,
    /// The identity of the target this source set compiles into; equal to a
    /// `build_target` row's `id`. Absent when the build model declares no
    /// owning target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    /// Workspace-relative path of the build file that justifies the source
    /// set. A finding about a source set anchors here, because the build file
    /// is what makes the claim true.
    pub build_file: String,
    /// `complete` or `incomplete`: whether the build evidence behind this row
    /// was read in full. A policy concluding from the absence of a source set
    /// must consult it.
    pub completeness: &'static str,
}

/// One artifact the build declares, as a query row (#2448).
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryBuildTarget {
    pub id: String,
    /// The name the build declares for the target, which is the name an
    /// architecture policy writes.
    pub name: String,
    /// The identity of the build project that produces this target; equal to
    /// the `id` of the `build_project` topology entity. Absent when the build
    /// model declares no owning project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_project_id: Option<String>,
    /// Workspace-relative path of the build file that declares the target.
    pub build_file: String,
    pub completeness: &'static str,
}

/// One dependency the build declares between two targets of this workspace
/// (#2448).
///
/// `from_id` and `to_id` are `build_target` row ids, so an architecture rule
/// relates two targets by id equality rather than by comparing names it read
/// out of two different places. The names travel too, because the rule an
/// author writes names the target the build names.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryTopologyEdge {
    /// The edge's stable identity, which includes the build file that declares
    /// it: two build files declaring the same dependency are two pieces of
    /// evidence and a finding anchors on one of them.
    pub id: String,
    /// The depending target's row id.
    pub from_id: String,
    /// The depended-on target's row id, absent when the depended-on coordinate
    /// is not a declared target of this workspace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_id: Option<String>,
    pub from_name: String,
    pub to_name: String,
    /// The build-declared scope of the dependency: `compile`, `runtime`,
    /// `test`, `provided`, `optional`, `feature_gated`, or `unknown`. The same
    /// vocabulary a resolved external dependency carries, so a rule about
    /// compile scope means one thing on both sides.
    pub scope: &'static str,
    /// Workspace-relative path of the build file that declares the dependency.
    /// This is the finding anchor.
    pub build_file: String,
    pub completeness: &'static str,
}

/// The build configuration one file is analyzed under, and the file's standing
/// in it, as a query row (#9048).
///
/// The row separates two claims a platform-specific rule must not conflate.
/// `os`, `arch` and `file_status` describe the configuration the analysis
/// selected, which a host or a toolchain default may have chosen. `os_scope`
/// and `arch_scope` describe the file's own constraint, independent of any
/// host: `any` is a platform-neutral file, which is never evidence that it is
/// built for one particular target.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeQueryBuildConfiguration {
    /// Identity of this file under this configuration.
    pub id: String,
    /// Identity of the selected configuration alone, equal on every file the
    /// same configuration selects.
    pub configuration_id: String,
    pub language: &'static str,
    /// Workspace-relative path of the file.
    pub path: String,
    /// The selected target triple: Rust's rustc target. Go has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The selected target operating system (Go's `GOOS`, Rust's
    /// `target_os`). Absent when the target is not one rustc knows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Where `os` came from: `configuration`, `toolchain` or `host`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_source: Option<&'static str>,
    /// The selected target architecture (Go's `GOARCH`, Rust's
    /// `target_arch`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_source: Option<&'static str>,
    /// `included`, `excluded` or `unknown`: whether the selected configuration
    /// compiles this file.
    pub file_status: &'static str,
    /// The file's build constraint in canonical spelling: filename suffix and
    /// directive conjoined. Absent for an unconstrained file; the directive as
    /// written when it is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint: Option<String>,
    /// `any`, `restricted`, `none` or `unknown`: which operating systems the
    /// constraint admits for some choice of every other tag.
    pub os_scope: &'static str,
    /// The admitted operating systems, space-separated, when `os_scope` is
    /// `restricted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_values: Option<String>,
    pub arch_scope: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch_values: Option<String>,
}

pub const BUILD_SETTING_SOURCE_LABELS: &[&str] = &["configuration", "toolchain", "host"];
pub const BUILD_FILE_STATUS_LABELS: &[&str] = &["included", "excluded", "unknown"];
pub const BUILD_TARGET_SCOPE_LABELS: &[&str] = &["any", "restricted", "none", "unknown"];
