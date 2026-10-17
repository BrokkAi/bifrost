#!/usr/bin/env bash

# Extract the staged inputs of the prepublish agent-plugin smoke: the exact
# Linux binary archive and the packaged plugin, each from a directory holding
# its tarball, and report where they landed.
#
# This was a `run: |` block in release-readiness.yml. The release gate stages
# the same inputs from the artifacts it just built (#3472).
#
# Usage: scripts/public/stage-agent-plugin-smoke.sh <binary-dir> <plugin-dir> <bin-name>
#
# Writes `binary=<path>` and `plugin=<path>` to GITHUB_OUTPUT when it is set,
# and to stdout otherwise.

set -euo pipefail

binary_dir="${1:?usage: stage-agent-plugin-smoke.sh BINARY_DIR PLUGIN_DIR BIN_NAME}"
plugin_dir="${2:?usage: stage-agent-plugin-smoke.sh BINARY_DIR PLUGIN_DIR BIN_NAME}"
bin_name="${3:?usage: stage-agent-plugin-smoke.sh BINARY_DIR PLUGIN_DIR BIN_NAME}"

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/fail.sh
source "$script_directory/../lib/fail.sh"

archive="$(find "$binary_dir" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
[[ -n "$archive" ]] || die "no binary archive under $binary_dir"
tar -C "$binary_dir" -xzf "$archive"
binary="$(find "$binary_dir" -type f -name "$bin_name" -print -quit)"
[[ -n "$binary" ]] || die "no $bin_name inside $archive"
chmod +x "$binary"

plugin_archive="$(find "$plugin_dir" -maxdepth 1 -type f -name 'bifrost-agent-*.tar.gz' -print -quit)"
[[ -n "$plugin_archive" ]] || die "no bifrost-agent-*.tar.gz under $plugin_dir"
tar -C "$plugin_dir" -xzf "$plugin_archive"
[[ -f "$plugin_dir/bifrost-agent/plugin.json" ]] || die "$plugin_archive did not extract to $plugin_dir/bifrost-agent"

{
  echo "binary=$binary"
  echo "plugin=$plugin_dir/bifrost-agent"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
