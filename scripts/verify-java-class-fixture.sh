#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/java-class-fixture-lib.sh"

work="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-java-fixture.XXXXXX")"
trap 'rm -rf "$work"' EXIT

assert_java_fixture_toolchain
compile_java_fixture "$work/classes"
write_java_fixture_manifest "$work/classes" >"$work/generated.sha256"
write_java_fixture_manifest "$java_fixture_dir/bin" >"$work/committed.sha256"

diff -u "$java_fixture_dir/classes.sha256" "$work/committed.sha256"
diff -u "$java_fixture_dir/classes.sha256" "$work/generated.sha256"
