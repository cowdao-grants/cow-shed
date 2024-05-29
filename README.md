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

### Tests

Fork testing is only used for the forward/reverse resolution testing of the ENS names for the proxies.

```bash
forge test -vvv --fork-url https://eth.llamarpc.com
```
### Examples

Two examples are included for reference:
1. [`./examples/mintDaiAndSwap.ts`](./examples/mintDaiAndSwap.ts) - In this example, the user approves the proxy contract to take actions on its behalf on the maker protocol and uses prehooks to just-in-time(JIT) borrow DAI right before the DAI gets swapped to COW.
1. [`./examples/swapAndBridge.ts`](./examples/swapAndBridge.ts) - In this example, the user uses the proxy address as the receiver for the swapped tokens and in the posthook it bridges the exact amount of swap output([weiroll](https://github.com/weiroll/weiroll) is used for this) to gnosis chain with user's address as the recipient.

The examples can be ran as follows:
```bash
yarn ts-node examples/<example.ts>
```
