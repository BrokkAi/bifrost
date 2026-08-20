#!/usr/bin/env bash
# Fetch the pinned external procedure-summary corpora and run the foundry join.
#
# The corpora are third-party content and are NOT vendored into this
# repository. Only small verbatim slices live under
# crates/bifrost-semantic-packs/testdata/summary-corpora/ so translator tests
# run offline.
#
#   CodeQL Models-as-Data  github/codeql        MIT
#   Joern flow semantics   joernio/joern        Apache-2.0
#
# semantic-packs/summary-corpora/pins.json is the single source of truth for
# the revision, the archive URL, its sha256, and the member path this script
# extracts. Bump a pin there and both this script and the join tool follow.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 WORK_DIR [REPORT_JSON] [PINNED_JVM_SOURCES]" >&2
  exit 2
fi

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work_dir=$1
report_path=${2:-${work_dir}/summary-corpus-join.json}
pins_path="${repository_root}/semantic-packs/summary-corpora/pins.json"
download_dir="${work_dir}/downloads"
extract_dir="${work_dir}/corpora"

mkdir -p "${download_dir}" "${extract_dir}"

# One node reader keeps the pins file the only place a revision is written.
read_pin() {
  node --input-type=module -e "
    import { readFileSync } from 'node:fs';
    const pins = JSON.parse(readFileSync('${pins_path}', 'utf8'));
    const record = pins.corpora.find((corpus) => corpus.corpus === '$1');
    if (!record) {
      throw new Error('pins.json declares no corpus $1');
    }
    process.stdout.write(String($2));
  "
}

fetch_corpus() {
  corpus=$1
  url=$(read_pin "${corpus}" "record.archive.url")
  sha256=$(read_pin "${corpus}" "record.archive.sha256")
  member=$(read_pin "${corpus}" "record.archive.member")
  archive="${download_dir}/${corpus}.tar.gz"

  # No --retry-all-errors here, unlike build-pinned-jvm-semantic-packs.sh: that
  # option needs curl 7.71 and this script is meant to run on any maintainer
  # machine. --retry still covers transient 5xx responses and timeouts.
  curl --fail --location --silent --show-error --retry 5 \
    --retry-delay 5 --connect-timeout 30 --output "${archive}" "${url}" \
    || { echo "error: cannot download the ${corpus} archive from ${url}" >&2; exit 1; }
  echo "${sha256}  ${archive}" | shasum -a 256 --check --status \
    || { echo "error: ${corpus} archive does not match its pinned sha256" >&2; exit 1; }
  tar -C "${extract_dir}" -xzf "${archive}" "${member}" \
    || { echo "error: ${corpus} archive has no member ${member}" >&2; exit 1; }
  echo "${extract_dir}/${member}"
}

# A command substitution runs in a subshell, so `exit 1` inside fetch_corpus
# ends only that subshell. Check each result here so a failed fetch stops the
# run instead of feeding an empty path to the join.
codeql_models=$(fetch_corpus codeql) || exit 1
joern_source=$(fetch_corpus joern) || exit 1

# The derived slot needs the pinned standard-library sources, which
# scripts/public/build-pinned-jvm-semantic-packs.sh already downloads and checksums.
# Pass the package root of an extracted src.zip module (for example
# "<extract>/java.base") as the third argument to this script; without it the
# run reports the derived slot as unpopulated instead of guessing.
jvm_sources=${3:-}
if [[ -n "${jvm_sources}" && ! -d "${jvm_sources}" ]]; then
  echo "error: ${jvm_sources} is not a directory of pinned Java sources" >&2
  exit 1
fi

cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- summary-corpus-join \
  "${pins_path}" "${codeql_models}" "${joern_source}" "${report_path}" ${jvm_sources:+"${jvm_sources}"}
