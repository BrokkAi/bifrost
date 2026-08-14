#!/usr/bin/env bash

java_fixture_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
java_fixture_dir="$java_fixture_root/tests/fixtures/testcode-java"
java_fixture_source_list="$java_fixture_dir/class-fixture-sources.txt"

assert_java_fixture_toolchain() {
  local javac_version javac_runtime
  javac_version="$(javac -version 2>&1)"
  javac_runtime="$(javac -J-version 2>&1)"

  if [[ "$javac_version" != "javac 21.0.8" ]] ||
    ! grep -Fq "Temurin-21.0.8+9" <<<"$javac_runtime"; then
    printf '%s\n' \
      "Java class fixture requires Eclipse Temurin 21.0.8+9." \
      "Found: $javac_version" \
      "$javac_runtime" >&2
    return 1
  fi
}

compile_java_fixture() {
  local output_dir="$1"
  local source relative_source
  local -a sources=()

  mkdir -p "$output_dir"
  while IFS= read -r source; do
    [[ -z "$source" || "$source" == \#* ]] && continue
    if [[ "$source" = /* || "$source" == *..* ]]; then
      printf 'Invalid Java fixture source path: %s\n' "$source" >&2
      return 1
    fi
    relative_source="$java_fixture_dir/$source"
    if [[ ! -f "$relative_source" ]]; then
      printf 'Missing Java fixture source: %s\n' "$source" >&2
      return 1
    fi
    sources+=("$relative_source")
  done <"$java_fixture_source_list"

  if [[ ${#sources[@]} -eq 0 ]]; then
    printf 'Java fixture source list is empty: %s\n' "$java_fixture_source_list" >&2
    return 1
  fi

  javac --release 21 -g -encoding UTF-8 -proc:none -implicit:none \
    -d "$output_dir" "${sources[@]}"
}

write_java_fixture_manifest() {
  local class_dir="$1"
  local class_file digest

  while IFS= read -r class_file; do
    read -r digest _ < <(shasum -a 256 "$class_dir/$class_file")
    printf '%s  %s\n' "$digest" "$class_file"
  done < <(
    cd "$class_dir"
    find . -type f -name '*.class' -print | sed 's#^\./##' | LC_ALL=C sort
  )
}
