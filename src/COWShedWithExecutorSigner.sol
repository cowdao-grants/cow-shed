// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {IERC1271} from "./IERC1271.sol";
import {LibAuthenticatedHooks} from "./LibAuthenticatedHooks.sol";
import {LibCowOrder} from "./LibCowOrder.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/// @title COWShedWithExecutorSigner
/// @notice A COWShed variant that is itself an EIP-1271 signer for CoW Protocol orders. When a
///         trusted executor contract is configured it delegates signature validity to it;
///         otherwise it verifies the owner's own signature over the full, human-readable order,
///         bound to this shed.
/// @dev Intended for setups where a manager/wrapper contract (the trusted executor) drives the
///      shed and decides which digests the shed will "sign" on-chain (e.g. by blessing a
///      settlement digest in transient storage), without the owner having to sign every order.
///      When no executor contract is set, the shed behaves as an owner-signed smart account: the
///      owner signs the CoW order (so a wallet shows the real order fields) under the shed's own
///      domain separator, and the order is carried in the EIP-1271 signature blob and checked to
///      reconstruct to exactly the digest CoW is settling. Both digests reuse `LibCowOrder`'s
///      canonical GPv2 `Order` type, differing only in the EIP-712 domain separator.
contract COWShedWithExecutorSigner is COWShed, IERC1271 {
    /// @notice GPv2 settlement contract whose domain separator CoW order digests are built under.
    address public immutable cowSettlement;

    bytes32 private constant EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor(address _cowSettlement) {
        cowSettlement = _cowSettlement;
    }

    /// @inheritdoc IERC1271
    /// @dev When a trusted executor *contract* is set, forwards to its `isValidSignature` and lets
    ///      it be authoritative. When no executor contract is set (unset or an EOA, neither of
    ///      which can implement EIP-1271), the `signature` must be `abi.encode(GPv2Order, ownerSig)`:
    ///      the order is reconstructed and required to hash (under the GPv2 domain separator) to
    ///      exactly `hash`, and `ownerSig` must be the owner's signature over the same order under
    ///      this shed's domain separator. Binding to the shed's domain separator prevents the
    ///      signature from being replayed to the owner's EOA (which signs under the GPv2 domain)
    ///      or to any other shed the owner controls. Returns `bytes4(0)` otherwise.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        address executor = _state().trustedExecutor;
        if (executor.code.length != 0) {
            return IERC1271(executor).isValidSignature(hash, signature);
        }

        // No executor contract configured: verify the owner's signature over the full order.
        (LibCowOrder.Data memory order, bytes memory ownerSignature) =
            abi.decode(signature, (LibCowOrder.Data, bytes));

        // The provided order must be exactly the order CoW is settling...
        if (LibCowOrder.hash(order, cowDomainSeparator()) != hash) {
            return bytes4(0);
        }

        // ...and the owner must have signed that same order under THIS shed's domain separator.
        // `tryRecover` returns address(0) for malformed signatures (never reverts).
        address recovered = ECDSA.tryRecover(orderSignedHash(order), ownerSignature);
        if (recovered != address(0) && recovered == _admin()) {
            return LibAuthenticatedHooks.MAGIC_VALUE_1271;
        }
        return bytes4(0);
    }

    /// @notice The GPv2 domain separator that CoW order digests are computed under.
    function cowDomainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPE_HASH, keccak256("Gnosis Protocol"), keccak256("v2"), block.chainid, cowSettlement
            )
        );
    }

    /// @notice The digest the owner signs to authorize `order` for this shed via EIP-1271: the
    ///         CoW order hashed under the shed's own domain separator (reusing `LibCowOrder`'s
    ///         canonical GPv2 `Order` type). Exposed so integrations can build the signature
    ///         off-chain.
    /// @param order The GPv2 order the owner is authorizing.
    function orderSignedHash(LibCowOrder.Data memory order) public view returns (bytes32) {
        return LibCowOrder.hash(order, domainSeparator());
    }
}
