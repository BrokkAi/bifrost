#!/usr/bin/env bash

# Preflight identity gate for a readiness run: prove the checkout is the exact
# commit that was asked for, that public master is where the caller observed it,
# that the release tag does not exist yet, and derive the build identity the
# matrix jobs must compile in.
#
# Environment:
#   PUBLIC_COMMIT         exact 40-character commit being qualified
#   EXPECTED_PUBLIC_HEAD  public master head the caller independently observed
#   PRIVATE_COMMIT        optional private source commit, validated when present
#   RELEASE_VERSION       release version without the v prefix
#   GITHUB_OUTPUT         file the resolved identity is appended to

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

: "${PUBLIC_COMMIT:?PUBLIC_COMMIT is required}"
: "${EXPECTED_PUBLIC_HEAD:?EXPECTED_PUBLIC_HEAD is required}"
: "${RELEASE_VERSION:?RELEASE_VERSION is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

[[ "$PUBLIC_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  die "public_commit must be a full lowercase commit SHA, not $PUBLIC_COMMIT"
[[ "$EXPECTED_PUBLIC_HEAD" =~ ^[0-9a-f]{40}$ ]] ||
  die "expected_public_head must be a full lowercase commit SHA, not $EXPECTED_PUBLIC_HEAD"
if [[ -n "${PRIVATE_COMMIT:-}" ]]; then
  [[ "$PRIVATE_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
    die "private_commit must be a full lowercase commit SHA, not $PRIVATE_COMMIT"
fi

checked_out="$(git rev-parse HEAD)"
[[ "$checked_out" == "$PUBLIC_COMMIT" ]] ||
  die "checkout is $checked_out but $PUBLIC_COMMIT was requested"

public_head="$(git ls-remote origin refs/heads/master | awk '{print $1}')"
[[ -n "$public_head" ]] || die "origin has no refs/heads/master to compare against"
[[ "$public_head" == "$EXPECTED_PUBLIC_HEAD" ]] ||
  die "public master is $public_head, but preflight was told to expect $EXPECTED_PUBLIC_HEAD"

# The binary compiles its own identity in, so deriving that identity from HEAD
# makes every commit produce a different binary -- including a commit that only
# records the binary's checksums. Name the last commit that touched a compiled
# input instead, so a checksum correction leaves the build alone. This job is
# the only one with full history; the build matrix checks out shallow and cannot
# see past its own commit, so resolve it here and hand it down.
build_identity="$(git log -1 --format=%H -- \
  src crates resources Cargo.toml Cargo.lock build.rs \
  rust-toolchain.toml .cargo/config.toml)"
[[ -n "$build_identity" ]] || die "no commit in this history touches a compiled input"
echo "build_identity=$build_identity" >> "$GITHUB_OUTPUT"
if [[ "$build_identity" != "$PUBLIC_COMMIT" ]]; then
  echo "Build identity $build_identity precedes the qualified commit; nothing compiled changed since."
fi

set +e
tag_refs="$(git ls-remote --exit-code --tags origin "refs/tags/v${RELEASE_VERSION}" 2>&1)"
tag_status=$?
set -e
case "$tag_status" in
  0)
    die "release tag v${RELEASE_VERSION} already exists; readiness must precede tagging"
    ;;
  2)
    [[ -z "$tag_refs" ]] || die "unexpected output while proving v${RELEASE_VERSION} absent: $tag_refs"
    ;;
  *)
    die "unable to prove release tag v${RELEASE_VERSION} is absent: $tag_refs"
    ;;
esac
echo "commit=$PUBLIC_COMMIT" >> "$GITHUB_OUTPUT"
