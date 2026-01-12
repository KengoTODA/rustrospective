#!/usr/bin/env bash
set -euo pipefail

spotbugs_version="4.9.8"
smoke_root="target/smoketest"
spotbugs_dir="${smoke_root}/spotbugs-${spotbugs_version}"
lib_dir="${spotbugs_dir}/lib"

if [[ ! -d "${lib_dir}" ]]; then
  mkdir -p "${smoke_root}"
  zip_file="${smoke_root}/spotbugs-${spotbugs_version}.zip"
  curl -L -o "${zip_file}" "https://github.com/spotbugs/spotbugs/releases/download/${spotbugs_version}/spotbugs-${spotbugs_version}.zip"
  unzip -q "${zip_file}" -d "${smoke_root}"
fi

if [[ ! -d "${lib_dir}" ]]; then
  echo "missing SpotBugs lib dir: ${lib_dir}" >&2
  exit 1
fi

log_file="${smoke_root}/spotbugs-smoke.log"
echo "smoke: writing output to ${log_file}"
: > "${log_file}"

while IFS= read -r jar_path; do
  echo "smoke: ${jar_path}"
  cargo run -- --input="${jar_path}" >> "${log_file}"
done < <(find "${lib_dir}" -type f -name "*.jar" | sort)
