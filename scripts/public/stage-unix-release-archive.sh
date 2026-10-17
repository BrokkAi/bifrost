#!/usr/bin/env bash

# Stage one Unix release archive from a built binary: the tarball a release
# publishes, with the licence notices beside the binary, and its SHA-256
# sidecar.
#
# This was a `run: |` block in release-readiness.yml, once per Linux and macOS
# target. The release gate now stages the Linux/x86 archive from the same
# script (#3472), so a drift in the archive layout fails there first.
#
# Usage: scripts/public/stage-unix-release-archive.sh <binary> <target> <release-tag>
#
# Run it from the repository root: the licence notices and README are read
# relative to the current directory, as the workflow block did.
#
# Environment:
#   DIST_DIR  where the archive and sidecar are written (default: dist)

set -euo pipefail

binary="${1:?usage: stage-unix-release-archive.sh BINARY TARGET RELEASE_TAG}"
target="${2:?usage: stage-unix-release-archive.sh BINARY TARGET RELEASE_TAG}"
release_tag="${3:?usage: stage-unix-release-archive.sh BINARY TARGET RELEASE_TAG}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

[[ -f "$binary" ]] || die "release binary does not exist: $binary"
bin_name="$(basename -- "$binary")"
dist_dir="${DIST_DIR:-dist}"

for notice in LICENSE.md README.md licenses/THIRD_PARTY_LICENSES.html licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt; do
  [[ -f "$notice" ]] || die "release archive input is missing: $notice"
done

stage="${bin_name}-${release_tag}-${target}"
mkdir -p "${dist_dir}/${stage}"
cp "$binary" "${dist_dir}/${stage}/"
cp LICENSE.md README.md licenses/THIRD_PARTY_LICENSES.html licenses/SUPPLEMENTAL_THIRD_PARTY_NOTICES.txt "${dist_dir}/${stage}/"
tar -C "$dist_dir" -czf "${dist_dir}/${stage}.tar.gz" "${stage}"
(cd "$dist_dir" && shasum -a 256 "${stage}.tar.gz" > "${stage}.tar.gz.sha256")
echo "Staged ${dist_dir}/${stage}.tar.gz"
