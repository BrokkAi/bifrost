#!/usr/bin/env bash

# Refuse to re-label an existing qualification bundle unless the corrected
# commit provably changed nothing that was built.
#
# Environment:
#   SOURCE_COMMIT  commit whose artifacts are being reused
#   PUBLIC_COMMIT  corrected commit the artifacts are being re-labelled for

set -euo pipefail

: "${SOURCE_COMMIT:?SOURCE_COMMIT is required}"
: "${PUBLIC_COMMIT:?PUBLIC_COMMIT is required}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

[[ "$SOURCE_COMMIT" != "$PUBLIC_COMMIT" ]] ||
  die "requalify_from_run already qualified ${PUBLIC_COMMIT}; dispatch a normal readiness run instead"
git merge-base --is-ancestor "$SOURCE_COMMIT" "$PUBLIC_COMMIT" ||
  die "${SOURCE_COMMIT} is not an ancestor of ${PUBLIC_COMMIT}; these are not the same release line"

# Only the paths scripts/public/sync-release-checksums.mjs writes. Any other change
# could have altered a built artifact, and reusing the artifacts would then be a
# false claim.
bash "$script_directory/check-checksum-only-diff.sh" "$SOURCE_COMMIT" "$PUBLIC_COMMIT" ||
  die "${SOURCE_COMMIT}..${PUBLIC_COMMIT} is not a checksum-only correction; run a full readiness instead"
