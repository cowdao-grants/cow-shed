# `cow-shed`

![`cow-shed`](https://i.imgur.com/n7GUxFC.png)

[`COWShed`](./src/COWShed.sol) is a user owned ERC1967 proxy deployed at a determininstic
address using `create2` with the user address as the `salt`.

This deterministic deployment allows users to set the proxy address as the `receiver` for
cowswap orders with pre/post hooks. At the first execution of hooks, the proxy gets deployed
for the user and the hooks are executed.

User signs a EIP712 message for the pre/post hooks which gets validated and only user signed
hooks are executed on the user's proxy. This allows users to confidently perform permissioned
actions in the hooks like:

1. transferring assets from the proxy to someone else.
2. use the proxy to add collateral or repay debt on a maker CDP or a aave debt position, etc.

The signed message type looks like:

```
ExecuteHooks(Call[] calls,bytes32 nonce,uint256 deadline)
Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)
```

The EOA signatures are expected to be 65 bytes long and to be encoded as `abi.encodePacked(r, s, v)`.

Nonces are used to ensure signed hooks are only executed once and they also allow users to revoke
the signed hooks in case they want to. And users must manage them.

The nonces are not constrained to be sequential, so multiple orders with hooks can be executed
out of order, but still validated. **However, nonces are implemented using a bitmap. And sequential
nonces will save some gas.**

The system also support smart contracts. In case of contracts, EIP1271 signatures are used to
authenticate the signed hooks.

The factory also implements an ENS forward and reverse resolver. When the factory is deployed, it is
also inited with an ENS name e.g. `cowhooks.eth`. For each proxy deployed on mainnet, it transfers the
ownership of the reverse resolver node `<address>.addr.reverse` back to the factory contract and it is
also set as the resolver. The reverse resolution will resolve to `<proxy-owner>.cowhooks.eth`.

At the time of initialization it also sets a subnode record for `<user>.cowhooks.eth` that resolves to
the `<proxy-address>`. This allows user to get their proxy address by doing a simple ens lookup for
`<user-address>.cowhooks.eth`. The reverse resolver will also allow anyone to lookup the proxy owner
from the proxy address.

```sh
# forward resolution
$ cast resolve-name <user>.cowhooks.eth
<proxy-address>

# reverse resolution
$ cast lookup-address <proxy-address>
<user>.cowhooks.eth
```

## Usage

### Deployments

As `cow-shed` makes use of determinstic deployment, it has the same deployment address across all EVM-compatible chains. The contracts are deployed to the following addresses:

- `COWShedFactory`: `0x00E989b87700514118Fa55326CD1cCE82faebEF6`
- `COWShed`: `0x2CFFA8cf11B90C9F437567b86352169dF4009F73` (implementation)

The contracts are deployed to the following networks:

- `mainnet`
- `gnosis`
- `arbitrum`
- `sepolia`
- `base`
- `polygon`
- `avalanche`

### Tests

Fork testing is only used for the forward/reverse resolution testing of the ENS names for the proxies.

```bash
forge test -vvv --fork-url https://eth.llamarpc.com
```

### Examples

Two examples are included for reference:

1. [`./examples/mintDaiAndSwap.ts`](./examples/mintDaiAndSwap.ts) - In this example, the user approves the proxy contract to take actions on its behalf on the maker protocol and uses prehooks to just-in-time(JIT) borrow DAI right before the DAI gets swapped to COW.
2. [`./examples/swapAndBridge.ts`](./examples/swapAndBridge.ts) - In this example, the user uses the proxy address as the receiver for the swapped tokens and in the posthook it bridges the exact amount of swap output([weiroll](https://github.com/weiroll/weiroll) is used for this) to gnosis chain with user's address as the recipient.
3. [`./examples/claimAndSwap.ts`](./examples/claimAndSwap.ts) - In this example, the user claims WETH from a Llama Pay vesting contract using a prehook right before swapping it to COW.

The examples can be ran as follows:

```bash
yarn ts-node examples/<example.ts>
```

### Deployment

#### 0. Pre-requisites

Even though the deterministic deployment is used, on the latest foundry versions, different addresses are generated.
It is required to use the following foundry toolchain version:

```shell
foundryup --install 1.2.1
```

```
$ forge --version
forge Version: 1.2.1-v1.2.1
Commit SHA: 42341d5c94947d566c21a539aead92c4c53837a2
Build Timestamp: 2025-05-26T04:44:55.696771378Z (1748234695)
Build Profile: maxperf
```

#### 1. Build

```shell
$ forge build
```

#### 2. Validate the deterministic addresses

You can simulate the deployment on a network where the contracts aren't present yet with the following command.

```shell
forge script 'script/DeployAndRecord.s.sol:DeployAndRecordScript' --sig "run(string)" "hooks.cow.eth" --rpc-url "$RPC_URL" -vvvv
```

If running on a network where the contracts are already deployed, the script is expected to revert.

You can also run the script without the `--rpc-url` parameter to see the expected deployment addresses and generate the file `deploymentAddresses.json`.

#### 3. Deploy

The deployment consists of two steps: deploying verified contract code on-chain and saving the compiler standard JSON input

```shell
forge script 'script/DeployAndRecord.s.sol:DeployAndRecordScript' --sig "run(string)" "hooks.cow.eth" --rpc-url "$RPC_URL" -vvvv --private-key "$PK" --broadcast
```

#### 4. Verify the deployed contracts

```shell
export ETHERSCAN_API_KEY='your API key here' # required only for etherscan based explorers

forge verify-contract --verifier etherscan --watch --rpc-url "$RPC_URL" 0x2cffa8cf11b90c9f437567b86352169df4009f73 COWShed --guess-constructor-args
forge verify-contract --verifier etherscan --watch --rpc-url "$RPC_URL" 0x00E989b87700514118Fa55326CD1cCE82faebEF6 COWShedFactory --guess-constructor-args
```

If this doesn't work, visit the block explorer web interface for each of the deployed contract and manually verify through the interface.
Choose "standard JSON input" as the verification method and use the files from `dev/standard-json-input`.

#### 5. Commit the deployment file

After successfully deploying the contracts, a deployment file is automatically generated in the `broadcast/Deploy.s.sol/` directory under the relevant chain subdirectory. Make sure to commit this file to the repository.

#### 6. Deployment addresses

The file [`networks.json`](./networks.json) lists all official deployments of the contracts in this repository by chain id.

Update the file with:

```sh
bash dev/generate-networks-file.sh > networks.json
```

#### 7. Update standard JSON input file, if needed

This is normally not necessary if deploying a contract to the same deterministic address of a previous deployment but it may be necessary if part of the contract code changed.

The standard JSON input files can be updated with the following command:

```sh
bash dev/generate-solc-standard-input.sh
```
