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
ExecuteHooks(Call[] calls,bytes32 nonce)
Call(address target,uint256 value,bytes callData,bool allowFailure)
```

The nonces are not constrained to be sequential, so multiple orders with hooks can be executed
out of order, but still validated.

The system also support smart contracts. In case of contracts, EIP1271 signatures are used to
authenticate the signed hooks.

## Usage

### Tests

```bash
forge test -vvv
```
