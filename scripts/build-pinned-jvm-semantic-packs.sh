#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIR WORK_DIR" >&2
  exit 2
fi

output_dir=$1
work_dir=$2
input_dir="${work_dir}/semantic-pack-inputs"
temurin_dir="${work_dir}/temurin"

mkdir -p "${input_dir}" "${temurin_dir}"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${input_dir}/kotlin-stdlib-2.2.20-sources.jar" \
  "https://repo1.maven.org/maven2/org/jetbrains/kotlin/kotlin-stdlib/2.2.20/kotlin-stdlib-2.2.20-sources.jar"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${input_dir}/scala-library-2.13.16-sources.jar" \
  "https://repo1.maven.org/maven2/org/scala-lang/scala-library/2.13.16/scala-library-2.13.16-sources.jar"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --retry-delay 5 --connect-timeout 30 \
  --output "${input_dir}/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.8_9.tar.gz" \
  "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.8%2B9/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.8_9.tar.gz"

cd "${input_dir}"
shasum -a 256 --check <<'CHECKSUMS'
27b9b8672ef33ae9c345b3e57d39b705560e7eca9ca2bf6485f323f612276c26  kotlin-stdlib-2.2.20-sources.jar
c02edc324e7db59c52115214a6ef36e2d78d0a50dff635eda4dcee5502b1dea5  scala-library-2.13.16-sources.jar
59422c2292ae4e76b87e00d8808dbe49cffa39af731e08bb0292ddb0af4e0261  OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.8_9.tar.gz
CHECKSUMS
tar -C "${temurin_dir}" -xzf OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.8_9.tar.gz
cp "${temurin_dir}/jdk-21.0.8+9/Contents/Home/lib/src.zip" src.zip
shasum -a 256 --check <<'CHECKSUMS'
5440baccc6c54b18671ab9cb9bf6ffdd7698d3a85ee74faa0b47b111312f200c  src.zip
CHECKSUMS

cd - >/dev/null
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate \
  "${output_dir}" \
  semantic-packs/jvm/temurin-jdk-21.0.8+9.json "${input_dir}/src.zip" \
  semantic-packs/jvm/kotlin-stdlib-2.2.20.json "${input_dir}/kotlin-stdlib-2.2.20-sources.jar" \
  semantic-packs/jvm/scala-library-2.13.16.json "${input_dir}/scala-library-2.13.16-sources.jar"
cargo run --locked --release --features release-tooling \
  -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify \
  "${output_dir}"
