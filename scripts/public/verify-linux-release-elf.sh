#!/usr/bin/env bash

set -euo pipefail

binary="${1:?usage: verify-linux-release-elf.sh BINARY TARGET_TRIPLE}"
target="${2:?usage: verify-linux-release-elf.sh BINARY TARGET_TRIPLE}"

[[ -f "$binary" ]] || {
  echo "ELF verification failed: binary does not exist: $binary" >&2
  exit 1
}
command -v readelf >/dev/null 2>&1 || {
  echo "ELF verification failed: readelf is required" >&2
  exit 1
}

case "$target" in
  x86_64-unknown-linux-gnu)
    expected_machine="Advanced Micro Devices X86-64"
    expected_interpreter="/lib64/ld-linux-x86-64.so.2"
    loader="ld-linux-x86-64.so.2"
    ;;
  aarch64-unknown-linux-gnu)
    expected_machine="AArch64"
    expected_interpreter="/lib/ld-linux-aarch64.so.1"
    loader="ld-linux-aarch64.so.1"
    ;;
  *)
    echo "ELF verification failed: unsupported target: $target" >&2
    exit 1
    ;;
esac

header="$(readelf -hW "$binary")"
machine="$(printf '%s\n' "$header" | awk -F: '/^[[:space:]]*Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }')"
[[ "$machine" == "$expected_machine" ]] || {
  echo "ELF verification failed: $target requires machine '$expected_machine', found '$machine'" >&2
  exit 1
}

program_headers="$(readelf -lW "$binary")"
interpreter="$(printf '%s\n' "$program_headers" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')"
[[ "$interpreter" == "$expected_interpreter" ]] || {
  echo "ELF verification failed: $target requires interpreter '$expected_interpreter', found '$interpreter'" >&2
  exit 1
}

version_info="$(readelf --version-info -W "$binary")"
mapfile -t glibc_versions < <(
  { printf '%s\n' "$version_info" | grep -oE 'GLIBC_[0-9]+([.][0-9]+)+' || true; } |
    sed 's/^GLIBC_//' |
    sort -Vu
)
(( ${#glibc_versions[@]} > 0 )) || {
  echo "ELF verification failed: no GLIBC symbol versions found" >&2
  exit 1
}
max_glibc="${glibc_versions[-1]}"
if [[ "$(printf '%s\n' "$max_glibc" '2.28' | sort -V | tail -n 1)" != '2.28' ]]; then
  echo "ELF verification failed: maximum GLIBC version is $max_glibc, expected at most 2.28" >&2
  exit 1
fi

dynamic="$(readelf -dW "$binary")"
mapfile -t needed < <(printf '%s\n' "$dynamic" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')
(( ${#needed[@]} > 0 )) || {
  echo "ELF verification failed: no dynamic dependencies found" >&2
  exit 1
}

declare -A allowed=(
  [libc.so.6]=1
  [libm.so.6]=1
  [libpthread.so.0]=1
  [libdl.so.2]=1
  [librt.so.1]=1
  [libgcc_s.so.1]=1
  ["$loader"]=1
)
has_libc=0
for library in "${needed[@]}"; do
  [[ "$library" == 'libc.so.6' ]] && has_libc=1
  [[ -n "${allowed[$library]:-}" ]] || {
    printf 'ELF verification failed: unexpected dynamic dependency %s; complete NEEDED set: %s\n' \
      "$library" "${needed[*]}" >&2
    exit 1
  }
done
(( has_libc == 1 )) || {
  printf 'ELF verification failed: libc.so.6 is missing; complete NEEDED set: %s\n' "${needed[*]}" >&2
  exit 1
}

printf 'Verified GNU/Linux ELF contract for %s\n' "$target"
printf '  machine: %s\n' "$machine"
printf '  interpreter: %s\n' "$interpreter"
printf '  maximum GLIBC version: %s\n' "$max_glibc"
printf '  NEEDED: %s\n' "${needed[*]}"
