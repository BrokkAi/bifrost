#!/usr/bin/env bash

# Refuse an npm tarball that carries a credential or repository file.
#
# This was a `run: |` block in release-readiness.yml; the release gate runs it
# on the tarballs it packages from the Linux/x86 archive (#3472).
#
# Usage: scripts/public/check-npm-tarballs.sh <tarball-directory>

set -euo pipefail

tarball_dir="${1:?usage: check-npm-tarballs.sh TARBALL_DIR}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

shopt -s nullglob
tarballs=("$tarball_dir"/*.tgz)
(( ${#tarballs[@]} > 0 )) || die "no npm tarballs under $tarball_dir"
for tarball in "${tarballs[@]}"; do
  if tar -tzf "$tarball" | grep -E '(^|/)([.]npmrc|[.]git|id_rsa|credentials)($|/)'; then
    die "unexpected sensitive path in $tarball"
  fi
done
echo "Inspected ${#tarballs[@]} npm tarballs under $tarball_dir"
