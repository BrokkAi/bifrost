#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
fixture="$root/tests/fixtures/csharp-external"
work="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-csharp-fixture.XXXXXX")"
trap 'rm -rf "$work"' EXIT

dotnet build "$fixture/ExternalLibrary.csproj" --configuration Release --nologo \
  -p:BaseIntermediateOutputPath="$work/obj/" \
  -p:OutputPath="$work/bin/" \
  -p:RestorePackagesPath="$work/packages/"

cmp "$work/bin/ExternalLibrary.dll" "$fixture/ExternalLibrary.dll"
(cd "$fixture" && shasum -a 256 -c ExternalLibrary.dll.sha256)
