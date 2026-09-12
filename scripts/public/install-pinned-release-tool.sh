#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 {cargo-about|cargo-zigbuild|ziglang} ROOT VERSION" >&2
  exit 64
}

[[ $# -eq 3 ]] || usage

tool=$1
root=$2
version=$3

case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) usage ;;
esac

find_binary() {
  local candidate=$1
  if [[ -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  if [[ -x "$candidate.exe" ]]; then
    printf '%s\n' "$candidate.exe"
    return 0
  fi
  return 1
}

reported_version() {
  local binary=$1
  shift
  "$binary" "$@" 2>/dev/null | tail -n 1
}

verify_or_install_cargo_tool() {
  local binary actual_version
  if binary=$(find_binary "$root/bin/$tool"); then
    actual_version=$(reported_version "$binary" --version)
    if [[ "$actual_version" == "$tool $version" ]]; then
      return
    fi
    printf '%s reports %s, expected %s; reinstalling\n' \
      "$binary" "${actual_version:-no version}" "$tool $version" >&2
  fi

  rm -rf -- "$root"
  mkdir -p -- "$root"
  cargo install --locked --version "$version" --root "$root" "$@" "$tool"

  binary=$(find_binary "$root/bin/$tool") || {
    echo "$tool was not installed into $root/bin" >&2
    return 1
  }
  actual_version=$(reported_version "$binary" --version)
  [[ "$actual_version" == "$tool $version" ]] || {
    echo "$tool reports ${actual_version:-no version}, expected $tool $version" >&2
    return 1
  }
}

verify_or_install_ziglang() {
  local binary actual_version
  if binary=$(find_binary "$root/bin/python-zig"); then
    actual_version=$(reported_version "$binary" version)
    if [[ "$actual_version" == "$version" ]]; then
      return
    fi
    printf 'python-zig reports %s, expected %s; reinstalling\n' \
      "${actual_version:-no version}" "$version" >&2
  fi

  rm -rf -- "$root"
  python3 -m venv "$root"
  "$root/bin/pip" install --disable-pip-version-check "ziglang==$version"

  binary=$(find_binary "$root/bin/python-zig") || {
    echo "python-zig was not installed into $root/bin" >&2
    return 1
  }
  actual_version=$(reported_version "$binary" version)
  [[ "$actual_version" == "$version" ]] || {
    echo "python-zig reports ${actual_version:-no version}, expected $version" >&2
    return 1
  }
}

case "$tool" in
  cargo-about)
    verify_or_install_cargo_tool --features cli
    ;;
  cargo-zigbuild)
    verify_or_install_cargo_tool
    ;;
  ziglang)
    verify_or_install_ziglang
    ;;
  *)
    usage
    ;;
esac
