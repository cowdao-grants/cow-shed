#!/bin/bash

set -o errexit -o nounset -o pipefail

repo_root_dir="$(git rev-parse --show-toplevel)"
output_folder="$repo_root_dir/dev/standard-json-input"

require_installed() {
  local command=$1
  if ! which -- "$command" >/dev/null; then
    echo "Required command \"$command\" not installed" >&2
    exit 1
  fi
}
generate_standard_json_input() {
  local contract_name=$1
  # Note: the address parameter is unused when using
  # `--show-standard-json-input`
  forge verify-contract --show-standard-json-input 0x0000000000000000000000000000000000000000 "$contract_name" \
    | jq \
    > "$output_folder/$contract_name.json"
}

require_installed jq
require_installed forge

generate_standard_json_input COWShed
generate_standard_json_input COWShedFactory
