#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/java-class-fixture-lib.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-java-fixture.XXXXXX")"
trap 'rm -rf "$work"' EXIT

assert_java_fixture_toolchain
compile_java_fixture "$work/classes"
write_java_fixture_manifest "$work/classes" >"$work/classes.sha256"

if [[ -L "$java_fixture_dir/bin" ]] ||
  [[ -n "$(find "$java_fixture_dir/bin" -type l -print -quit)" ]] ||
  [[ -L "$java_fixture_dir/classes.sha256" ]]; then
  printf 'Refusing to regenerate Java fixtures through a symlink.\n' >&2
  exit 1
fi
find "$java_fixture_dir/bin" -type f -name '*.class' -delete
cp -R "$work/classes/." "$java_fixture_dir/bin/"
cp "$work/classes.sha256" "$java_fixture_dir/classes.sha256"
