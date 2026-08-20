#!/usr/bin/env bash

# Resolve the qualification bundle a metadata-only re-qualification reuses.
#
# Environment:
#   GH_TOKEN           token able to read runs and artifacts in PUBLIC_REPOSITORY
#   PUBLIC_REPOSITORY  owner/name of the repository holding the source run
#   SOURCE_RUN_ID      readiness run whose artifacts are reused
#   RELEASE_VERSION    release version without the v prefix
#   GITHUB_OUTPUT      file the resolved source commit and artifact name go to

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

: "${PUBLIC_REPOSITORY:?PUBLIC_REPOSITORY is required}"
: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${RELEASE_VERSION:?RELEASE_VERSION is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

run_json="$(gh api "repos/${PUBLIC_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}")"
conclusion="$(jq -r '.conclusion' <<<"$run_json")"
[[ "$conclusion" == "success" ]] ||
  die "run ${SOURCE_RUN_ID} concluded $conclusion; only a successful qualification can be reused"
workflow_path="$(jq -r '.path' <<<"$run_json")"
[[ "$workflow_path" == ".github/workflows/release-readiness.yml" ]] ||
  die "run ${SOURCE_RUN_ID} is $workflow_path, not a release-readiness run"

# The artifact name carries the commit that was qualified, which is the
# authority here. A run's head_sha only says which ref it was dispatched from,
# which for a workflow_dispatch is not the input.
artifact="$(gh api "repos/${PUBLIC_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}/artifacts" \
  --jq '[.artifacts[] | select(.name | startswith("release-qualification-")) | select(.expired == false)] | first')"
[[ "$artifact" != "null" ]] ||
  die "run ${SOURCE_RUN_ID} has no unexpired release-qualification artifact"
name="$(jq -r '.name' <<<"$artifact")"
source_commit="${name#release-qualification-}"
source_commit="${source_commit%%-v*}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] ||
  die "artifact $name does not name a full commit SHA"
[[ "$name" == "release-qualification-${source_commit}-v${RELEASE_VERSION}" ]] ||
  die "artifact $name does not qualify v${RELEASE_VERSION}"

{
  echo "source_commit=$source_commit"
  echo "artifact_name=$name"
} >> "$GITHUB_OUTPUT"
echo "Reusing $name from run ${SOURCE_RUN_ID}"
