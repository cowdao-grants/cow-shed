#!/bin/bash

set -o errexit -o pipefail -o nounset

repo_root_dir="$(git rev-parse --show-toplevel)"
manual_file="$repo_root_dir/broadcast/networks-manual.json"

# Generate JSON from broadcast deployment files.
#
# Later entries win when the same contract was deployed more than once on a chain, so the
# files are fed in deployment order. Iterating the glob directly would instead order them by
# path, which sorts "Deploy.s.sol" before "DeployAndRecord.s.sol" and so lets an older run
# override a newer one. Broadcast timestamps are seconds in older files and milliseconds in
# newer ones, hence the normalisation.
generated=$(for deployment in "$repo_root_dir/broadcast/"*"/"*"/"*".json"; do
  timestamp=$(jq -r '(.timestamp // 0) | if . > 100000000000 then . / 1000 else . end | floor' <"$deployment")
  printf '%s\t%s\n' "$timestamp" "$deployment"
done | sort -n -k1,1 | cut -f2- | while IFS= read -r deployment; do
  # Extract chain ID from folder name
  chain_id=${deployment%/*}
  chain_id=${chain_id##*/}

  # Extract contract info per chain.
  #
  # `Deploy.s.sol` deploys `COWShedFactory` twice: once for the plain shed and once for the
  # Composable CoW one. Both carry the same `contractName`, so without disambiguation the
  # second silently overwrites the first and one factory address is lost. A factory whose
  # constructor argument is the `COWShedForComposableCoW` deployed in the same run is
  # therefore recorded under its own name.
  jq --arg chainId "$chain_id" '
    [.transactions[] | select(.transactionType == "CREATE2") | select(.hash != null)] as $txs
    | (($txs | map(select(.contractName == "COWShedForComposableCoW")) | first | .contractAddress // "")
       | ascii_downcase) as $composableShed
    | $txs[]
    | . as $tx
    | (if $tx.contractName == "COWShedFactory"
          and $composableShed != ""
          and ((($tx.arguments // [])[0] // "") | ascii_downcase) == $composableShed
        then "COWShedFactoryForComposableCoW"
        else $tx.contractName
        end) as $name
    | {($name): {($chainId): {address: $tx.contractAddress, transactionHash: $tx.hash }}}
  ' <"$deployment"
done | jq --sort-keys --null-input 'reduce inputs as $item ({}; . *= $item)')

# Merge with manual file if it exists
if [[ -f "$manual_file" ]]; then
  # Validate that the manual file contains valid JSON
  if ! jq empty "$manual_file" 2>/dev/null; then
    echo "Error: $manual_file is not valid JSON." >&2
    exit 1
  fi
  
  jq --slurp --sort-keys 'reduce .[] as $item ({}; . *= $item)' \
    <(printf '%s' "$generated") "$manual_file"
else
  printf '%s\n' "$generated"
fi
