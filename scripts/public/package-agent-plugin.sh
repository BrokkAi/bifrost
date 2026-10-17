#!/usr/bin/env bash

# Package the portable agent plugin exactly as a release publishes it: the
# plugin directory with the repository licence copied in, as a tarball with a
# SHA-256 sidecar.
#
# This was a `run: |` block in release-readiness.yml. The release gate packages
# the plugin with the same script and launches that package in the prepublish
# smoke (#3472), so the packaging boundary is exercised before projection.
#
# Usage: scripts/public/package-agent-plugin.sh <release-tag> <package-root>
#
# Run it from the repository root: the plugin directory and LICENSE.md are
# read relative to the current directory, as the workflow block did.
#
# Environment:
#   DIST_DIR  where the archive and sidecar are written (default: dist)

set -euo pipefail

release_tag="${1:?usage: package-agent-plugin.sh RELEASE_TAG PACKAGE_ROOT}"
package_root="${2:?usage: package-agent-plugin.sh RELEASE_TAG PACKAGE_ROOT}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

dist_dir="${DIST_DIR:-dist}"
[[ -f plugins/bifrost-agent/plugin.json ]] || die "run from the repository root: plugins/bifrost-agent/plugin.json not found"
[[ ! -e "$package_root/bifrost-agent" ]] || die "package root already holds a plugin copy: $package_root/bifrost-agent"
# A checkout that ran `npm ci` in the plugin would ship node_modules.
[[ ! -e plugins/bifrost-agent/node_modules ]] || die "plugins/bifrost-agent/node_modules exists; package the plugin before installing its dependencies"

mkdir -p "$package_root" "$dist_dir"
cp -R plugins/bifrost-agent "$package_root/bifrost-agent"
cp LICENSE.md "$package_root/bifrost-agent/"
tar -C "$package_root" -czf "${dist_dir}/bifrost-agent-${release_tag}.tar.gz" bifrost-agent
sha256sum "${dist_dir}/bifrost-agent-${release_tag}.tar.gz" > "${dist_dir}/bifrost-agent-${release_tag}.tar.gz.sha256"
echo "Packaged ${dist_dir}/bifrost-agent-${release_tag}.tar.gz"
