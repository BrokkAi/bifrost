use super::*;

/// One compilation input set the build declares, as a query row (#2448).
///
/// The row is reached from a file through `source_set_of`, so its existence is
/// itself the statement "the build says this file compiles here". A file no
/// build file claims produces no row and an explicit diagnostic; it never
/// produces a row derived from the file's path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
