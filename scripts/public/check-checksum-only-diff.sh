#!/usr/bin/env bash

# Prove a git diff is a launcher-checksum correction and nothing else.
#
# Two release gates need this and used to state it independently: the metadata
# sync confirms its own working tree before committing, and a metadata-only
# re-qualification confirms the corrected commit against the commit whose
# artifacts it reuses. Both claims are the same claim, and both are false in the
# same two ways -- a file outside the projection set, or a version string moving
# under cover of a checksum edit.
#
# The allowlist is read from the single writer of those files rather than
# restated here; see scripts/public/sync-release-checksums.mjs.
#
# Usage:
#   scripts/public/check-checksum-only-diff.sh                  # working tree
#   scripts/public/check-checksum-only-diff.sh <from> <to>      # commit range

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

allowed="$(node "$script_directory/sync-release-checksums.mjs" paths | LC_ALL=C sort)"

changed="$(git diff --name-only "$@" | LC_ALL=C sort)"
[[ -n "$changed" ]] || die "no change to verify; expected a launcher-checksum correction"
printf 'Changed:\n%s\n' "$changed"

unexpected="$(comm -23 <(printf '%s\n' "$changed") <(printf '%s\n' "$allowed"))"
if [[ -n "$unexpected" ]]; then
  printf '  %s\n' "$unexpected" >&2
  die "changed files outside the tracked checksum projections"
fi

# A version bump hiding inside an allowlisted file still means the change is not
# a checksum correction; the readiness artifacts and the promoted binaries would
# both be describing a different release.
if git diff -U0 "$@" | grep -E '^[+-][[:space:]]*"?(version|binaryVersion|minimumBinaryVersion)"?[[:space:]]*[:=]'; then
  die "a version string changed; this gate admits checksum corrections only"
fi
