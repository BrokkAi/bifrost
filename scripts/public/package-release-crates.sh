#!/usr/bin/env bash

# Build the exact crate archives a readiness run qualifies, alongside their
# SHA-256 sidecars and registry publish metadata.
#
# Environment:
#   RELEASE_VERSION  version the archives must carry, without the v prefix
#   RUNNER_TEMP      scratch directory for the package target and cargo metadata
#   DIST_DIR         where the qualified archives are collected (default: dist)

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_directory/../.." && pwd)"
# shellcheck source=scripts/lib/release-crates.sh
source "$script_directory/../lib/release-crates.sh"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

: "${RELEASE_VERSION:?RELEASE_VERSION is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
dist_dir="${DIST_DIR:-dist}"

cd "$repository_root"

bash scripts/public/check-workspace-packages.sh

mkdir -p "$dist_dir"
metadata="${RUNNER_TEMP}/cargo-metadata.json"
badges="${RUNNER_TEMP}/crate-badges.json"
cargo metadata --format-version 1 --no-deps > "$metadata"
printf '{}\n' > "$badges"

for package in "${RELEASE_CRATES[@]}"; do
  CARGO_TARGET_DIR="${RUNNER_TEMP}/crate-target" cargo package \
    --quiet --locked --allow-dirty --no-verify --package "$package" \
    --manifest-path Cargo.toml "${RELEASE_CRATE_PATCH_ARGS[@]}"
  archive="${RUNNER_TEMP}/crate-target/package/${package}-${RELEASE_VERSION}.crate"
  [[ -f "$archive" ]] || die "cargo package produced no $archive"
  archive_name="$(basename "$archive")"
  cp "$archive" "$dist_dir/"
  sha256sum "$archive" > "$dist_dir/${archive_name}.sha256"

  publish_metadata="$dist_dir/${archive_name}.metadata.json"
  node scripts/public/generate-crate-publish-metadata.mjs \
    --cargo-metadata-file "$metadata" \
    --package "$package" \
    --version "$RELEASE_VERSION" \
    --badges-file "$badges" \
    --output-file "$publish_metadata"
  [[ "$(jq -r '.name // empty' "$publish_metadata")" == "$package" ]] ||
    die "$publish_metadata does not describe $package"
  [[ "$(jq -r '.vers // empty' "$publish_metadata")" == "$RELEASE_VERSION" ]] ||
    die "$publish_metadata does not describe version $RELEASE_VERSION"
  jq -e '.deps | type == "array"' "$publish_metadata" >/dev/null ||
    die "$publish_metadata has no dependency array"
done

echo "Packaged ${#RELEASE_CRATES[@]} release crates at version $RELEASE_VERSION into $dist_dir"
